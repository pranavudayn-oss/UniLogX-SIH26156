
import csv
import json
import re
from io import StringIO
from typing import Any
from ..parsers.base_parser import BaseParser

IP = r"(?:\d{1,3}\.){3}\d{1,3}"

class GenericJSONParser(BaseParser):
    name="generic_json"; display_name="Generic JSON"; vendor="Generic"; format="json_generic"
    version="1.0"; supported_source="application"; description="Generic structured JSON event parser"; mapping_file=None; status="Active"
    supported_fields=["timestamp","source_ip","destination_ip","user","action","outcome","category","event_type","message"]
    def can_parse(self,text): 
        try: return isinstance(json.loads(text),dict)
        except Exception: return False
    def parse_line(self,line):
        obj=json.loads(line)
        def pick(*keys):
            for k in keys:
                if k in obj and obj[k] is not None: return obj[k]
            return None
        src=pick("source_ip","sourceIP","src","src_ip","client_ip","sourceIPAddress","origin")
        dst=pick("destination_ip","destinationIP","dst","dst_ip","server_ip","targetIPAddress","target")
        user=pick("user","username","userName","principal","actor")
        action=pick("action","act","operation","eventName","method","verb")
        outcome=pick("outcome","result","status","verdict")
        ts=pick("timestamp","time","eventTime","datetime","date","@timestamp")
        msg=pick("message","msg","log","description","event")
        category=pick("category","eventCategory") or "application"
        return {"timestamp":ts,"source_ip":src,"destination_ip":dst,"user":user,"action":action,
                "outcome":outcome,"message":str(msg) if msg is not None else None,
                "category":category,"event_type":pick("event_type","eventType","type") or "json_event",
                "raw_fields":obj}

class WindowsEventJSONParser(GenericJSONParser):
    name="windows_event_json"; display_name="Windows Event JSON"; vendor="Microsoft"; format="windows_event_json"
    supported_source="windows"; description="Windows Event/EVTX-to-JSON style security and system event parser"
    def can_parse(self,text):
        try:
            o=json.loads(text)
            s=json.dumps(o).lower()
            return ("eventid" in s and ("system" in o or "provider" in s)) or "windows-event" in s or "winevent" in s
        except Exception:return False
    def parse_line(self,line):
        o=json.loads(line); sys=o.get("System",o.get("system",{})) or {}
        eid=sys.get("EventID",sys.get("eventid",o.get("EventID")))
        provider=sys.get("Provider",{}) or {}
        if isinstance(provider,dict): provider=provider.get("Name")
        msg=o.get("message") or o.get("Message") or f"Windows Event ID {eid}" if eid is not None else "Windows event"
        return {"timestamp":sys.get("TimeCreated") or o.get("timestamp"),
                "user":o.get("user") or o.get("User"),
                "action":o.get("action") or f"event_{eid}" if eid is not None else o.get("action"),
                "outcome":o.get("outcome") or o.get("result"),
                "message":msg,"category":"authentication" if str(eid) in {"4624","4625","4634","4648"} else "system",
                "event_type":"windows_event","event_code":eid,"provider":provider,"raw_fields":o}

class SuricataEVEParser(GenericJSONParser):
    name="suricata_eve"; display_name="Suricata EVE JSON"; vendor="Suricata"; format="suricata_eve"
    supported_source="ids_ips"; description="Suricata EVE JSON alert/flow/DNS/HTTP event parser"
    def can_parse(self,text):
        try:
            o=json.loads(text); return isinstance(o,dict) and ("event_type" in o and any(k in o for k in ("src_ip","dest_ip","alert","flow","http","dns")))
        except Exception:return False
    def parse_line(self,line):
        o=json.loads(line); alert=o.get("alert") or {}
        action=alert.get("action") if isinstance(alert,dict) else None
        outcome="failure" if alert else "success"
        return {"timestamp":o.get("timestamp"),"source_ip":o.get("src_ip"),"source_port":o.get("src_port"),
                "destination_ip":o.get("dest_ip"),"destination_port":o.get("dest_port"),
                "transport":o.get("proto"),"action":action or ("alert" if alert else o.get("event_type")),
                "outcome":outcome,"severity":str(alert.get("severity")) if isinstance(alert,dict) and alert.get("severity") is not None else None,
                "message":alert.get("signature") if isinstance(alert,dict) else o.get("event_type"),
                "category":"intrusion_detection","event_type":o.get("event_type","eve"),"raw_fields":o}

class SnortAlertParser(BaseParser):
    name="snort_alert"; display_name="Snort Alert"; vendor="Snort"; format="snort_alert"; version="1.0"
    supported_source="ids_ips"; description="Snort alert text parser"; mapping_file=None; status="Active"
    supported_fields=["source_ip","source_port","destination_ip","destination_port","action","outcome","severity","message"]
    PAT=re.compile(r'(?P<msg>.*?)(?P<src>'+IP+r')(?::(?P<sp>\d+))?\s*[-=]>\s*(?P<dst>'+IP+r')(?::(?P<dp>\d+))?',re.I)
    def can_parse(self,text): return "snort" in text.lower() or bool(self.PAT.search(text))
    def parse_line(self,line):
        m=self.PAT.search(line); 
        if not m: raise ValueError("Not a Snort alert")
        d=m.groupdict()
        return {"source_ip":d["src"],"source_port":int(d["sp"]) if d["sp"] else None,"destination_ip":d["dst"],
                "destination_port":int(d["dp"]) if d["dp"] else None,"action":"alert","outcome":"failure",
                "category":"intrusion_detection","event_type":"alert","message":d["msg"].strip()}

class LinuxAuthParser(BaseParser):
    name="linux_auth"; display_name="Linux Auth Log"; vendor="Linux"; format="linux_auth"; version="1.0"
    supported_source="linux"; description="Linux auth/sshd authentication log parser"; mapping_file=None; status="Active"
    supported_fields=["timestamp","source_ip","user","action","outcome","message","category"]
    PAT=re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+\S+\s+(?P<proc>sshd|sudo|login)(?:\[\d+\])?:\s*(?P<msg>.*)$',re.I)
    def can_parse(self,text): return bool(self.PAT.search(text.strip())) and bool(re.search(r"(failed|accepted|authentication|invalid user|sudo)",text,re.I))
    def parse_line(self,line):
        m=self.PAT.search(line.strip()); 
        if not m: raise ValueError("Not a Linux auth log")
        msg=m.group("msg"); low=msg.lower()
        ips=re.findall(IP,msg); um=re.search(r"(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9_.-]+)",msg,re.I)
        success="accepted" in low or "successful" in low
        return {"timestamp":m.group("ts"),"source_ip":ips[0] if ips else None,"user":um.group(1) if um else None,
                "action":"login","outcome":"success" if success else "failure","message":msg,
                "category":"authentication","event_type":"user_login"}

class ApacheErrorParser(BaseParser):
    name="apache_error"; display_name="Apache Error Log"; vendor="Apache"; format="apache_error"; version="1.0"
    supported_source="web_server"; description="Apache HTTP error log parser"; mapping_file=None; status="Active"
    supported_fields=["timestamp","severity","message","category","event_type","source_ip"]
    PAT=re.compile(r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<sev>[^\]]+)\]\s*(?:\[[^\]]+\]\s*)?(?P<msg>.*)$')
    def can_parse(self,text): return bool(self.PAT.search(text.strip())) and "error" in text.lower() or bool(re.search(r"\[\w+\]\s+\[[\w]+\]",text))
    def parse_line(self,line):
        m=self.PAT.search(line.strip()); 
        if not m: raise ValueError("Not Apache error log")
        d=m.groupdict(); ips=re.findall(IP,d["msg"])
        return {"timestamp":d["ts"],"severity":d["sev"],"message":d["msg"],"source_ip":ips[0] if ips else None,
                "category":"web","event_type":"error","outcome":"failure"}

class DockerJSONParser(GenericJSONParser):
    name="docker_json"; display_name="Docker JSON Log"; vendor="Docker"; format="docker_json"
    supported_source="container"; description="Docker json-file log driver format"; status="Active"
    def can_parse(self,text):
        try:
            o=json.loads(text); return isinstance(o,dict) and "log" in o and ("stream" in o or "time" in o)
        except Exception:return False
    def parse_line(self,line):
        o=json.loads(line); return {"timestamp":o.get("time"),"message":str(o.get("log","")).rstrip(),
            "category":"container","event_type":"container_log","stream":o.get("stream"),"raw_fields":o}

class MySQLLogParser(BaseParser):
    name="mysql_log"; display_name="MySQL Error/General Log"; vendor="MySQL"; format="mysql_log"; version="1.0"
    supported_source="database"; description="Common MySQL log line parser"; status="Active"; mapping_file=None
    supported_fields=["timestamp","user","source_ip","action","outcome","message"]
    def can_parse(self,text):
        return bool(re.search(r"\b(?:mysqld|mysql)\b",text,re.I)) and bool(re.search(r"(error|connect|access|ready|aborted)",text,re.I))
    def parse_line(self,line):
        ips=re.findall(IP,line); userm=re.search(r"user[=:]\s*([A-Za-z0-9_.-]+)",line,re.I)
        low=line.lower(); outcome="failure" if any(x in low for x in ("error","aborted","denied")) else "success"
        return {"message":line,"source_ip":ips[0] if ips else None,"user":userm.group(1) if userm else None,
                "action":"database_event","outcome":outcome,"category":"database","event_type":"mysql"}

class PostgreSQLLogParser(BaseParser):
    name="postgresql_log"; display_name="PostgreSQL Log"; vendor="PostgreSQL"; format="postgresql_log"; version="1.0"
    supported_source="database"; description="Common PostgreSQL log parser"; status="Active"; mapping_file=None
    supported_fields=["timestamp","user","source_ip","action","outcome","message"]
    def can_parse(self,text):
        return bool(re.search(r"\b(?:postgres|postgresql)\b",text,re.I)) and bool(re.search(r"(LOG|ERROR|FATAL|STATEMENT|connection)",text,re.I))
    def parse_line(self,line):
        ips=re.findall(IP,line); userm=re.search(r"user[=:]\s*([A-Za-z0-9_.-]+)",line,re.I)
        low=line.lower(); outcome="failure" if any(x in low for x in ("error","fatal")) else "success"
        return {"message":line,"source_ip":ips[0] if ips else None,"user":userm.group(1) if userm else None,
                "action":"database_event","outcome":outcome,"category":"database","event_type":"postgresql"}

class CSVEventParser(BaseParser):
    name="csv_event"; display_name="CSV Structured Event"; vendor="Generic"; format="csv"
    supported_source="application"; description="Single-line CSV event parser using headerless common fields"; status="Active"; mapping_file=None
    supported_fields=["timestamp","source_ip","destination_ip","action","outcome","message"]
    def can_parse(self,text):
        return text.count(",")>=3 and not text.lstrip().startswith(("{","<"))
    def parse_line(self,line):
        row=next(csv.reader(StringIO(line)))
        if len(row)<4: raise ValueError("CSV row has fewer than 4 fields")
        keys=["timestamp","source_ip","destination_ip","action","outcome","message","user","severity"]
        return {keys[i]:row[i].strip() for i in range(min(len(row),len(keys)))}

class GenericTextParser(BaseParser):
    name="generic_text"; display_name="Generic Security Text"; vendor="Generic"; format="generic_text"; version="1.0"
    supported_source="generic"; description="Safe fallback parser for recognizable security/system text"; status="Active"; mapping_file=None
    supported_fields=["source_ip","destination_ip","action","outcome","message","category","event_type"]
    def can_parse(self,text):
        low=text.lower()
        return bool(re.search(IP,text)) or any(k in low for k in ("login","connection","blocked","denied","failed","error","warning","accepted"))
    def parse_line(self,line):
        ips=re.findall(IP,line); low=line.lower()
        outcome="failure" if any(k in low for k in ("failed","failure","denied","blocked","error","fatal","unauthorized")) else ("success" if any(k in low for k in ("accepted","success","allowed","permit")) else "unknown")
        action="deny" if outcome=="failure" else ("allow" if outcome=="success" else "observe")
        return {"source_ip":ips[0] if ips else None,"destination_ip":ips[1] if len(ips)>1 else None,
                "action":action,"outcome":outcome,"message":line,"category":"general","event_type":"text_event"}
