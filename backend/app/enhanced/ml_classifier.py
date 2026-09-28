
"""
Dependency-free ML-style log classifier.

This is a small multinomial Naive Bayes classifier implemented with standard
Python only. It is intentionally lightweight for the offline MVP. Exact
parser rules are preferred; this classifier is used when no high-confidence
rule matches.
"""
import math
import re
from collections import Counter, defaultdict

TOKEN_RE = re.compile(r"[A-Za-z0-9_./:=%-]+")

TRAINING = {
    "nginx": [
        '192.168.1.10 - - [27/Sep/2026:12:00:01 +0000] "GET /admin HTTP/1.1" 403 532',
        '10.0.0.4 - - [27/Sep/2026:12:00:02 +0000] "POST /login HTTP/1.1" 401 421',
    ],
    "syslog": [
        '<34>Sep 27 12:00:01 host sshd: Failed password for user from 10.0.0.5 port 22',
        'Sep 27 12:00:02 router sshd: Accepted password for admin from 10.0.0.5 port 22',
    ],
    "cisco_asa": [
        'Sep 27 12:00:01 %ASA-6-106015: Deny TCP (no connection) from 10.0.0.5/1234 to 10.0.0.8/443',
        'Sep 27 12:00:02 %ASA-6-302013: Built outbound TCP connection',
    ],
    "cloud_json": [
        '{"eventTime":"2026-09-27T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"10.0.0.5","awsRegion":"us-east-1"}',
        '{"eventName":"CreateUser","userIdentity":{"userName":"admin"},"sourceIPAddress":"10.0.0.5"}',
    ],
    "suricata_eve": [
        '{"timestamp":"2026-09-27T12:00:00Z","event_type":"alert","src_ip":"10.0.0.5","dest_ip":"10.0.0.8","alert":{"signature":"ET SCAN","severity":2}}',
        '{"event_type":"flow","src_ip":"10.0.0.5","dest_ip":"10.0.0.8","proto":"TCP"}',
    ],
    "snort_alert": [
        '[**] [1:1000001:1] TEST ALERT [**] 10.0.0.5:1234 -> 10.0.0.8:443',
        'snort alert: suspicious traffic 10.0.0.5 -> 10.0.0.8',
    ],
    "linux_auth": [
        'Sep 27 12:00:01 server sshd[123]: Failed password for invalid user admin from 10.0.0.5 port 22',
        'Sep 27 12:00:02 server sshd[123]: Accepted password for pranav from 10.0.0.5 port 22',
    ],
    "apache_error": [
        '[Sun Sep 27 12:00:01.000000 2026] [error] [client 10.0.0.5] File not found',
        '[Sun Sep 27 12:00:02.000000 2026] [warn] configuration warning',
    ],
    "docker_json": [
        '{"log":"application failed to start\\n","stream":"stderr","time":"2026-09-27T12:00:00Z"}',
        '{"log":"server started\\n","stream":"stdout","time":"2026-09-27T12:00:01Z"}',
    ],
    "mysql_log": [
        '2026-09-27T12:00:01 mysqld: Error connecting user=admin from 10.0.0.5',
        'mysqld: ready for connections',
    ],
    "postgresql_log": [
        '2026-09-27 12:00:01 UTC [123] ERROR: connection failed user=admin from 10.0.0.5',
        'postgres: LOG: connection authorized user=admin',
    ],
    "windows_event_json": [
        '{"System":{"EventID":4625,"Provider":{"Name":"Microsoft-Windows-Security-Auditing"}},"message":"An account failed to log on"}',
        '{"System":{"EventID":4624},"message":"An account was successfully logged on"}',
    ],
    "generic_json": [
        '{"timestamp":"2026-09-27T12:00:00Z","source_ip":"10.0.0.5","action":"login","outcome":"failure"}',
        '{"time":"2026-09-27T12:00:01Z","message":"application event","status":"ok"}',
    ],
    "csv_event": [
        '2026-09-27T12:00:00Z,10.0.0.5,10.0.0.8,deny,failure,blocked connection',
        '2026-09-27T12:00:01Z,10.0.0.5,10.0.0.8,GET,success,request',
    ],
    "generic_kv": [
        'src=10.0.0.5 dst=10.0.0.8 dpt=22 proto=TCP act=deny',
        'user=admin src=10.0.0.5 action=login status=failed',
    ],
    "generic_text": [
        'connection denied from 10.0.0.5 to 10.0.0.8',
        'authentication failed for admin',
    ],
}

class LogTypeClassifier:
    def __init__(self, training=None):
        self.training = training or TRAINING
        self.classes=list(self.training)
        self.vocab=set()
        self.class_counts=Counter()
        self.token_counts=defaultdict(Counter)
        self.total_tokens=Counter()
        for label, samples in self.training.items():
            for sample in samples:
                toks=self._tokens(sample)
                self.class_counts[label]+=1
                self.token_counts[label].update(toks)
                self.total_tokens[label]+=len(toks)
                self.vocab.update(toks)
        self.total_samples=sum(self.class_counts.values())

    @staticmethod
    def _tokens(text):
        return [t.lower() for t in TOKEN_RE.findall(text)]

    def predict(self,text, top_k=3):
        toks=self._tokens(text)
        if not toks: return []
        V=max(1,len(self.vocab))
        scores=[]
        for c in self.classes:
            score=math.log((self.class_counts[c]+1)/(self.total_samples+len(self.classes)))
            denom=self.total_tokens[c]+V
            counts=self.token_counts[c]
            for t in toks:
                score += math.log((counts.get(t,0)+1)/denom)
            scores.append((c,score))
        scores.sort(key=lambda x:x[1],reverse=True)
        max_score=scores[0][1]
        exps=[math.exp(s-max_score) for _,s in scores]
        total=sum(exps) or 1
        return [(c,round(e/total,4)) for (c,_),e in zip(scores[:top_k],exps[:top_k])]

CLASSIFIER=LogTypeClassifier()
