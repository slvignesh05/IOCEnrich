#!/usr/bin/env bash
set -euo pipefail


# simple helper: install missing pip packages from requirements.txt
python - <<'PY'
import pkgutil, sys, subprocess
reqs = open('requirements.txt').read().splitlines()
missing = []
for r in reqs:
pkg = r.split('>=')[0].split('==')[0]
if not pkgutil.find_loader(pkg):
missing.append(r)
if missing:
print('Installing missing packages:', missing)
subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing)
else:
print('All python packages present')
PY


ES_URL=${ES_URL:-http://elasticsearch:9200}


# wait for ES
echo "Waiting for Elasticsearch at ${ES_URL}..."
for i in {1..60}; do
if curl -s ${ES_URL} | grep -q 'cluster_name'; then
echo "Elasticsearch is up"
break
fi
sleep 2
done


# run ES setup
python es_setup.py --es ${ES_URL} --index ${ES_INDEX:-ioc-enriched}


# run enrichment - loop forever to pick up new detects periodically
while true; do
python ioc_enrich.py --es ${ES_URL} --index ${ES_INDEX:-ioc-enriched}
echo "Sleeping 60s before next poll..."
sleep 60
done
