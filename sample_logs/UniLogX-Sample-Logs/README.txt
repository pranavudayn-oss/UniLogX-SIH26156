================================================================================
           UniLogX — Universal Log Pre-Processing & Forensic Traceability
                     Judge Testing Kit & Sample Log Package
================================================================================

1. WHAT IS UNILOGX?
-------------------
UniLogX is a high-performance, lossless log pre-processing, normalization, and
forensic traceability framework designed for heterogeneous security operations.
It ingests logs from disparate sources (firewalls, cloud audit trails, web
servers, authentication systems, intrusion detection systems, databases, and
custom services), preserves byte-exact raw evidence with SHA-256 cryptographic
verification, automatically detects formats, normalizes fields into an Elastic
Common Schema (ECS)-aligned taxonomy, enriches network ports offline, isolates
malformed or unrecognized records into Quarantine with actionable diagnostics,
and provides unified search, analytics, and tamper-evident evidence exports.

2. PURPOSE OF THIS TESTING KIT
------------------------------
This package provides 175 realistic, synthetic log entries organized into 17
specialized folders covering every parser implemented in the codebase (both core
and additive parsers), plus deliberately unknown/malformed logs designed to test
the quarantine workflow.

No real enterprise or sensitive data is included: all IP addresses use RFC 1918
private addresses or RFC 5737 documentation subnets (e.g., 192.168.x.x, 10.x.x.x,
198.51.100.x, 203.0.113.x), and all usernames/hostnames are synthetic.

3. FOLDER STRUCTURE & PARSER MAPPING
------------------------------------
UniLogX-Sample-Logs/
│
├── README.txt
│
├── apache_error/             -> Apache HTTP Server error logs (AH00124, AH01630)
│   └── apache_error.log         (10 entries — Expected: PARSED successfully)
│
├── cisco_asa/                -> Cisco ASA firewall connection & security events
│   └── cisco_asa.log            (10 entries — Expected: PARSED successfully)
│
├── cloud_json/               -> AWS CloudTrail structured JSON audit trails
│   └── cloudtrail.json          (10 entries — Expected: PARSED successfully)
│
├── csv_event/                -> Structured single-line CSV security events
│   └── csv_events.log           (10 entries — Expected: PARSED successfully)
│
├── docker_json/              -> Docker container JSON-file log driver streams
│   └── docker_containers.json   (10 entries — Expected: PARSED successfully)
│
├── generic_json/             -> Application-level structured JSON logs
│   └── application_events.json  (10 entries — Expected: PARSED successfully)
│
├── generic_kv/               -> Firewall & appliance key=value / CEF logs
│   └── firewall_kv.log          (10 entries — Expected: PARSED successfully)
│
├── generic_text/             -> Generic security & network audit text
│   └── security_text.log        (10 entries — Expected: PARSED successfully)
│
├── linux_auth/               -> Linux SSH & sudo authentication logs
│   └── linux_auth.log           (10 entries — Expected: PARSED successfully)
│
├── mysql_log/                -> MySQL Server error, connection & audit logs
│   └── mysql_server.log         (10 entries — Expected: PARSED successfully)
│
├── nginx/                    -> Nginx HTTP access logs in Common Log Format
│   └── nginx_access.log         (10 entries — Expected: PARSED successfully)
│
├── postgresql_log/           -> PostgreSQL connection, error & query logs
│   └── postgresql_server.log    (10 entries — Expected: PARSED successfully)
│
├── snort_alert/              -> Snort IDS/IPS alert messages with IP arrows
│   └── snort_alert.log          (10 entries — Expected: PARSED successfully)
│
├── suricata_eve/             -> Suricata EVE JSON network security events
│   └── suricata_eve.json        (10 entries — Expected: PARSED successfully)
│
├── syslog/                   -> Standard RFC 3164 / RFC 5424 syslog messages
│   └── standard_syslog.log      (10 entries — Expected: PARSED successfully)
│
├── windows_event_json/       -> Windows Security & System Event logs in JSON
│   └── windows_event.json       (10 entries — Expected: PARSED successfully)
│
└── unknown_quarantine/       -> Intentionally unsupported / malformed records
    ├── corrupted_records.log    (5 entries — Expected: QUARANTINED)
    ├── malformed_payloads.log   (5 entries — Expected: QUARANTINED)
    └── unsupported_telemetry.log(5 entries — Expected: QUARANTINED)

Total Entries: 175 (160 Parsable across 16 parsers + 15 Quarantine demonstrations)

4. EXPECTED RESULTS SUMMARY
---------------------------
- Successfully Parsed Files (Folders 1–16):
  Total: 160 entries across 16 parsers.
  Expected outcome: 100% processed into normalized events.
  0 quarantined.
  Each entry maps to its respective parser with extracted timestamps, IPs,
  ports, actions, outcomes, and categories, while retaining the untouched
  raw log and SHA-256 hash.

- Intentionally Quarantined Files (Folder 17: unknown_quarantine/):
  Total: 15 entries across 3 files.
  Expected outcome: 100% quarantined.
  0 processed.
  These logs deliberately contain unknown industrial protocols (SCADA, Modbus,
  Zigbee, CANBUS), corrupted delimiters, non-standard system crash dumps, and
  binary chunks that match NO registered parser or safe fallback.
  Each record is safely isolated in Quarantine with diagnostic error causes
  (e.g., "No matching parser found") without halting or crashing the pipeline.

5. HOW TO UPLOAD SAMPLES IN THE UNILOGX DASHBOARD
-------------------------------------------------
Step 1: Open the UniLogX Web Dashboard (typically http://localhost:5173 or your
        deployed production URL).
Step 2: On the Dashboard or "Ingest Logs" page, locate the "Universal Lossless
        Log Ingestion" dropzone.
Step 3: Click "Choose File" and select any log file from the extracted package
        (e.g., cisco_asa/cisco_asa.log, nginx/nginx_access.log, or
        unknown_quarantine/malformed_payloads.log).
Step 4: Click the blue "Process Log" button.
Step 5: View the real-time ingestion response banner showing:
        - Ingestion ID (e.g. ingest-a1b2c3d4)
        - Count of normalized events processed
        - Count of quarantined records
        - Detected format / parser name

6. WHAT THE JUDGE SHOULD OBSERVE
--------------------------------
1. Supported Parsers in Action:
   Navigate to the "Parsers" page to see all registered parsers with live
   processed event counters incrementing.

2. Normalization & Field Extraction:
   Navigate to the "Events" page to view normalized records in an Elastic
   Common Schema (ECS) taxonomy, including source IP, destination IP, ports,
   action (allow/deny), outcome (success/failure), and category.

3. Raw Log & Forensic Traceability Coexistence:
   Click any row in the Events table to open the Forensic Event Details Modal.
   Notice the side-by-side coexistence of normalized ECS fields alongside the
   byte-exact original raw log, SHA-256 cryptographic digest, trace ID, and
   file line number.

4. Offline Port Enrichment:
   Notice that standard ports (e.g., port 443 -> HTTPS, port 22 -> SSH,
   port 80 -> HTTP) are enriched offline without external network calls.

5. Quarantine Isolation & Diagnostics:
   Navigate to the "Quarantine" page after uploading any file from
   unknown_quarantine/. Observe that failed logs are safely isolated with exact
   line numbers, source files, and root-cause diagnostic reasons (e.g.
   "No matching parser found"). Click any quarantine record to view diagnostic
   details or test the reprocessing workflow.
================================================================================
