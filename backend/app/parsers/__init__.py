from .cisco_asa_parser import CiscoASAParser
from .nginx_parser import NginxParser
from .cloud_json_parser import CloudJSONParser
from .syslog_parser import SyslogParser
from .generic_kv_parser import GenericKVParser

PARSERS = [CloudJSONParser(), NginxParser(), CiscoASAParser(), SyslogParser(), GenericKVParser()]
