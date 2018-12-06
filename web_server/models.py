
from sqlalchemy import Column, DateTime, String
from database import Base
import datetime


class Telemetry(Base):
    __tablename__ = 'telemetry'
    ts = Column(DateTime, primary_key=True)
    hostname = Column(String(100), nullable=False)
    domain = Column(String(50), nullable=False)
    ip = Column(String(20), nullable=False)
    filepath = Column(String(256), nullable=False)
    hash = Column(String(100), nullable=False)

    def __init__(self):
        self.ts = datetime.datetime.now()

    def __repr__(self):
        return self.domain + " " + self.ip + " " + self.hostname + " " + self.filepath + " " + self.hash + "\n"

    def serialize(self):
        return {"ts": self.ts, "hostname": self.hostname, "domain": self.domain, "filepath": self.filepath,
                "ip": self.ip,  "hash": self.hash}


class Commands(Base):
    __tablename__ = 'commands'

    ts = Column(DateTime, primary_key=True)
    hostname = Column(String(100), primary_key=True, nullable=False)
    command = Column(String(256), nullable=False)
    command_args = Column(String(256), nullable=False)
    status = Column(String(100), nullable=False)
    result = Column(String(2048), nullable=False)
    hash = Column(String(100), nullable=False)

    def __init__(self):
        self.ts = datetime.datetime.now()

    def __repr__(self):
        return {"hostname": self.hostname, "command": self.command, "command_args": self.command_args,
                "status": self.status, "result": self.result, "hash": self.hash}

    def serialize(self):
        return {"ts": self.ts, "hostname": self.hostname, "command": self.command, "command_args": self.command_args,
                "status": self.status, "result": self.result, "hash": self.hash}


class Analysis(Base):
    __tablename__ = 'analysis'

    ts = Column(DateTime)
    hash = Column(String(100), primary_key=True, nullable=False)
    system = Column(String(10), primary_key=True, nullable=False)
    filepath = Column(String(256), nullable=False)
    status = Column(String(100), nullable=True)
    link = Column(String(256), nullable=True)
    result = Column(String(2048), nullable=True)

    def __init__(self):
        self.ts = datetime.datetime.now()

    def __repr__(self):
        return self.system + " " + self.filepath + " " + self.status + " " + self.link + " " + self.result + "\n"

    def serialize(self):
        return {"ts": self.ts, "hash": self.hash, "system": self.system, "filepath": self.filepath,
                "status": self.status,  "link": self.link, "result": self.result}