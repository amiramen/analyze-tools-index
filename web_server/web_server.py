import argparse
from flask import request, Flask, render_template, jsonify
from sqlalchemy import desc
from database import  db_session, init_db
from models import Telemetry, Analysis, Commands
import os
from werkzeug.utils import secure_filename
import json
import atexit
from apscheduler.scheduler import Scheduler
import requests
import datetime

app = Flask(__name__)
app.debug = True
app.template_debug = True

cron = Scheduler(daemon=True)
cron.start()


UPLOADED_PATH = "uploaded"
COLOR_BY_STATUS = dict(done="info", new="warning", done_good="success", done_bad="danger", sending="info")
DESCRIPTION_BY_STATUS =  dict(done="In Process", new="In Process", done_good="Legitimate", done_bad="Malicious", sending="In Process")

@app.route("/", methods=['GET', 'POST'])
def enterprise_status():
    status_counter = dict(done=0, new=0, done_good=0, done_bad=0, total=0)
    all_process_table = []
    for row in  Telemetry.query.order_by(desc(Telemetry.ts)).all():
        #file_name = os.path.basename(row.filepath)
        vt_hash_result = Analysis.query.filter_by(hash=row.hash, system="vt").first()
        cuckoo_hash_result = Analysis.query.filter_by(hash=row.hash, system="cuckoo").first()
        path, filename = row.filepath.rsplit("\\", 1)
        if cuckoo_hash_result is not None:
            cuckoo_link = cuckoo_hash_result.link
        else:
            cuckoo_link = "#"

        if vt_hash_result is not None:
            all_process_table.append(dict(color=COLOR_BY_STATUS[vt_hash_result.status],
                 status_text=DESCRIPTION_BY_STATUS[vt_hash_result.status],
                 time=str(row.ts)[:16],
                 process_name=filename,
                 domain=row.domain,
                 ip=row.ip,
                 file_path=path,
                 file_hash=row.hash,
                 full_path=row.filepath.replace("\\", "\\\\"),
                 machine=row.hostname,
                 vt_link=vt_hash_result.link,
                 vt_result=vt_hash_result.result,
                 cuckoo_link=cuckoo_link))
        else:
            all_process_table.append(dict(color=COLOR_BY_STATUS[vt_hash_result.status],
                                          time=str(row.ts)[:16],
                                          process_name=filename,
                                          domain=row.domain,
                                          ip=row.ip,
                                          file_path=path,
                                          file_hash=row.hash,
                                          full_path=row.filepath.replace("\\", "\\\\"),
                                          machine=row.hostname,
                                          vt_result="-",
                                          vt_link="#",
                                          cuckoo_link=cuckoo_link))
        if vt_hash_result.status == "sending":
            vt_hash_result.status = "new"
        status_counter[vt_hash_result.status] += 1
        status_counter["total"] += 1
    return render_template("pages/machine_status.html",all_process_table = all_process_table,status_counter=status_counter)

@app.route("/machine/<hostname>", methods=['GET', 'POST'])
def machine_status(hostname):
    print (Telemetry.query.all())
    return ("Hello World!")


@app.route("/telemetry/<hostname>",  methods=['POST'])
def process_client_telemetry(hostname):
    print ("telemetry: " + (hostname))
    if not request.json:
        return ("Waiting for json", 400)
    mydata = request.json
    t = Telemetry()
    #t.ts = mydata.get("ts")
    t.domain = mydata.get("domain")
    t.ip = mydata.get("ip")
    t.hostname = hostname
    t.filepath = mydata.get("filepath")
    t.hash = mydata.get("hash")
    db_session.add(t)

    exist_hash = Analysis.query.filter(Analysis.hash == mydata.get("hash"))
    if exist_hash.first() is None:
        a = Analysis()
        a.hash = mydata.get("hash")
        a.filepath = mydata.get("filepath")
        a.system = "vt"
        a.status = "new"
        db_session.add(a)

    db_session.commit()

    return ("Got telemetry",200)


@app.route("/send_command/",  methods=['POST'])
def process_command():
    mydata = request.form
    print (mydata)
    t = Commands()
    t.ts = datetime.datetime.now()
    t.hostname = mydata.get("hostname")
    t.command = mydata.get("command")
    t.status = "new"
    t.result = ""
    t.command_args = mydata.get("filepath")
    t.hash = mydata.get("hash")
    db_session.add(t)

    db_session.commit()

    return ("Got command",200)

@cron.interval_schedule(seconds=15)
def virustotal_analysis():
    global db_session
    print "Check for new entries to send to VT...",
    entry = Analysis.query.filter_by(status="new").first()
    if entry is None:
        print "No records to send to VT."
        return
    print("send to vt: " + entry.hash)
    entry.status = "sending"
    db_session.commit()
    #raw_vt_result = vt.Send(entry.hash)
    vt_result = json.loads(raw_vt_result)
    try:
        if vt_result["response_code"] != 200 and vt_result["error"] is not None:
            entry.status = "new"
        elif vt_result["response_code"] != 200:
            entry.status = "new"
        elif vt_result["results"]["positives"] is not None and vt_result["results"]["positives"] > 2:
            entry.status = "done_bad"
            entry.link = vt_result["results"]["permalink"]
        else:
            entry.status = "done_good"
            entry.link = vt_result["results"]["permalink"]

        entry.result = raw_vt_result
        db_session.commit()
    except Exception, e:
        print "send to vt error:" , e


@app.route("/check_for_vt",  methods=['GET'])
def check_new_files_submit_vt():
    virustotal_analysis()
    return "OK\n"

@app.route("/telemetry/<hostname>",  methods=['GET'])
def post_process_client_telemetry(hostname):
    return render_template('form.html')


@app.route("/command/<hostname>",  methods=['GET'])
def process_client_command(hostname):
    commands = Commands.query.filter(Commands.hostname == hostname).filter(Commands.status != "done")
    if commands.first() is None:
        return ("No command", 204)
    else:
        s = jsonify(commands=[cmd.serialize() for cmd in commands])
        return s

@app.route("/process_file/<hostname>/<hash>",  methods=['POST'])
def process_client_file(hostname, hash):
    f = request.files['file']
    f.save(os.path.join(UPLOADED_PATH, secure_filename(f.filename)))
    command_entry = Commands.query.filter(Commands.hash == hash)
    if command_entry.first() is not None:
        #command_entry.status = "done"
        db_session.delete(command_entry.first())

        fin = open(UPLOADED_PATH + "/" + f.filename, 'rb')
        files = {'file': fin}
        r = requests.post("http://sandbox.etp-research.info:8090/tasks/create/submit", files=files)
        print r
        task_ids = r.json()["task_ids"]
        print task_ids[0]
        #command_entry.result = "http://sandbox.etp-research.info:8000/analysis/"+task_ids[0]+"/summary"

        a = Analysis()
        a.hash = hash
        a.filepath = f.filename
        a.system = "cuckoo"
        a.status = "done"
        a.link = "http://sandbox.etp-research.info:8000/analysis/" + str(task_ids[0]) + "/summary"
        db_session.add(a)

        db_session.commit()


    return 'file uploaded successfully'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', default="127.0.0.1", help="Specify the host IP address")
    parser.add_argument('-p', '--port', default=9090, help="Specify port to listen on")
    parser.add_argument('-d', '--debug', default=True, help="Run in debug mode", action="store_true")
    parser.add_argument('-db', '--database', help="Path to sqlite database - Not Implemented")
    args = parser.parse_args()
    init_db()
    if not os.path.isdir(UPLOADED_PATH):
        os.makedirs(UPLOADED_PATH)
    app.run(host=args.host, port=args.port, debug=args.debug)
    atexit.register(lambda: cron.shutdown(wait=False))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()