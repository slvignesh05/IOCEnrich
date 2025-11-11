#!/usr/bin/env python3
import argparse, time, requests, json


parser = argparse.ArgumentParser()
parser.add_argument('--es', default='http://localhost:9200')
parser.add_argument('--index', default='ioc-enriched')
args = parser.parse_args()


# Create pipeline
pipeline = {
"processors": [
{"set": {"field": "vt_malicious_count", "value": "{{virustotal.data.attributes.last_analysis_stats.malicious}}", "override": True}},
{"set": {"field": "vt_total_engines", "value": "{{virustotal.data.attributes.last_analysis_stats.total}}", "override": True}}
]
}


print('Creating ingest pipeline...')
r = requests.put(f"{args.es}/_ingest/pipeline/vt_extract", json=pipeline)
print(r.status_code, r.text)


# create the index (if not exists) with mapping for Grafana
mapping = {
"mappings": {
"properties": {
"timestamp": {"type":"date","format":"epoch_millis"},
"hash": {"type":"keyword"},
"vt_malicious_count": {"type":"integer"},
"vt_total_engines": {"type":"integer"}
}
}
}


print('Creating index if missing...')
r = requests.put(f"{args.es}/{args.index}", json=mapping)
print(r.status_code, r.text)


print('Done ES setup')
