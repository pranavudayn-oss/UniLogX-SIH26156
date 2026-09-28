# UniLogX Architecture

Enterprise source → ingestion → detection → parser plugin → field extraction → normalization → validation/traceability → enrichment → unified event store/dashboard.

Unknown or invalid events branch into the quarantine store. Raw events remain available for forensic traceability.
