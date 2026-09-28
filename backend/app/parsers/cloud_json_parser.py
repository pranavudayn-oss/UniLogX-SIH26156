import json
from .base_parser import BaseParser

class CloudJSONParser(BaseParser):
    name = "cloud_json"
    display_name = "CloudTrail JSON"
    vendor = "AWS"
    format = "json"
    version = "1.0"
    supported_source = "cloud_provider"
    description = "AWS CloudTrail and structured JSON security event parser"
    supported_fields = [
        "source_ip", "user", "action", "outcome", "error_code",
        "cloud_region", "category", "event_type"
    ]
    mapping_file = "cloud_json.yaml"
    status = "Active"

    def can_parse(self, text: str) -> bool:
        try:
            obj = json.loads(text)
            return isinstance(obj, dict) and any(k in obj for k in ("eventTime", "eventName", "sourceIPAddress", "userIdentity", "awsRegion"))
        except Exception:
            return False

    def parse_line(self, line: str):
        obj = json.loads(line)
        identity = obj.get("userIdentity") or {}
        error_code = obj.get("errorCode")
        outcome = "failure" if error_code and str(error_code).lower() not in {"0", "success", "none"} else "success"
        return {
            "timestamp": obj.get("eventTime"),
            "action": obj.get("eventName"),
            "source_ip": obj.get("sourceIPAddress"),
            "user": identity.get("userName") or identity.get("arn"),
            "outcome": outcome,
            "error_code": error_code,
            "cloud_region": obj.get("awsRegion"),
            "message": obj.get("eventSource") or obj.get("eventName"),
            "category": "cloud",
            "event_type": "iam_activity",
            "raw_fields": obj,
        }
