# IOC Enrichment — Dockerized project

This repository contains a fully dockerized IOC enrichment pipeline that:

Pulls detections from CrowdStrike (Falcon) via FalconPy and extracts file hashes.

Queries VirusTotal v3 for each hash to enrich IOC context.

Indexes enriched IOC documents into Elasticsearch.

Visualizes results in Grafana (Elasticsearch datasource + a starter dashboard).

Everything is orchestrated with Docker Compose. The enrichment service includes a startup script that checks for required tools / Python packages and installs them if missing, so the container will self-bootstrap.

File tree

```
ioc-enrichment-dockerized/
├─ docker-compose.yml
├─ .env.example
├─ enrich/
│  ├─ Dockerfile
│  ├─ entrypoint.sh
│  ├─ requirements.txt
│  ├─ ioc_enrich.py
│  └─ es_setup.py
├─ grafana/
│  ├─ provisioning/
│  │  ├─ datasources/datasource.yml
│  │  └─ dashboards/dashboard.yml
│  └─ dashboards/dashboard.json
└─ README.md
```
Important: you will provide the API keys (CrowdStrike client id/secret and VirusTotal API key) by creating a .env file from .env.example before starting the stack.
