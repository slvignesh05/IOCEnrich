#!/usr/bin/env python3
"""
ioc_enrich.py (alerts version)
- Pull alerts from CrowdStrike (Alerts API via FalconPy)
- Extract file hashes from alert JSON
- Query VirusTotal v3 for each hash
- Index enriched IOC doc into Elasticsearch with ingest pipeline 'vt_extract'
"""

import os, time, json, logging, argparse
from elasticsearch import Elasticsearch
import requests
from falconpy import Alerts
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument('--es', default=os.getenv('ES_URL','http://localhost:9200'))
parser.add_argument('--index', default=os.getenv('ES_INDEX','ioc-enriched'))
args = parser.parse_args()

VT_API = os.getenv('VIRUSTOTAL_API_KEY')
FALCON_CLIENT_ID = os.getenv('FALCON_CLIENT_ID')
FALCON_CLIENT_SECRET = os.getenv('FALCON_CLIENT_SECRET')

es = Elasticsearch(args.es)
HEADERS_VT = {'x-apikey': VT_API}

def recursive_find_hashes(obj):
    hashes = set()
    if isinstance(obj, dict):
        for k,v in obj.items():
            if isinstance(v, str):
                s = v.strip().lower()
                if len(s) in (32,40,64) and all(c in '0123456789abcdef' for c in s):
                    hashes.add(s)
            else:
                hashes |= recursive_find_hashes(v)
    elif isinstance(obj, list):
        for item in obj:
            hashes |= recursive_find_hashes(item)
    elif isinstance(obj, str):
        s = obj.strip().lower()
        if len(s) in (32,40,64) and all(c in '0123456789abcdef' for c in s):
            hashes.add(s)
    return hashes

def vt_lookup(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    r = requests.get(url, headers=HEADERS_VT, timeout=30)
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 404:
        return {'error':'not_found','hash':hash_value}
    elif r.status_code == 429:
        logging.warning('VT rate limit reached; sleeping 60s')
        time.sleep(60)
        return vt_lookup(hash_value)
    else:
        logging.error('VT lookup failed %s: %s', r.status_code, r.text)
        return {'error':'vt_error','status_code':r.status_code,'body':r.text}

def index_doc(doc, index=args.index):
    """Index using ingest pipeline that extracts vt_malicious_count"""
    try:
        es.index(index=index, id=doc.get('hash'), pipeline='vt_extract', body=doc)
    except Exception as e:
        logging.exception("ES index failed: %s", e)

def get_alert_ids(alerts_client, filter_str=None, limit=200):
    """
    Use Alerts.query_alerts_v2 (GetQueriesAlertsV2) to fetch alert identifiers (composite ids or ids).
    Return a list of ids / composite_ids (strings).
    """
    # prefer the v2 helper if available
    params = {}
    if filter_str:
        params['filter'] = filter_str
    params['limit'] = limit

    # try v2 call
    for method in ('query_alerts_v2', 'query_alerts_v1', 'get_queries_alerts_v2', 'get_queries_alerts_v1'):
        if hasattr(alerts_client, method):
            logging.info("Using Alerts.%s", method)
            func = getattr(alerts_client, method)
            try:
                resp = func(**params) if method.startswith('query') else func(parameters=params)
            except TypeError:
                # some helpers want different arg names; fallback to no args
                resp = func()
            body = resp.get('body', {}) if isinstance(resp, dict) else {}
            # try common shapes
            ids = []
            if isinstance(body, dict):
                if 'resources' in body and isinstance(body['resources'], list):
                    ids = body['resources']
                elif 'composite_ids' in body and isinstance(body['composite_ids'], list):
                    ids = body['composite_ids']
                elif 'ids' in body and isinstance(body['ids'], list):
                    ids = body['ids']
            # flatten strings if needed
            if ids:
                return ids
    logging.warning("No alert ids found from query response")
    return []

def fetch_alert_entities(alerts_client, ids):
    """
    Given a list of ids or composite_ids, call the entities fetch API to retrieve full alert JSONs.
    Attempts multiple possible helper names to maximize compatibility across FalconPy versions.
    """
    if not ids:
        return []
    # Some APIs accept comma-separated ids, some want list in body. Try multiple.
    candidates = [
        ('get_alerts_v2', {'ids': ids}),
        ('get_alerts_v1', {'ids': ids}),
        ('get_alerts', {'ids': ids}),
        ('get_alerts_v2', {'ids': ','.join(ids)}),
        ('post_entities_alerts_v2', {'ids': ids}),
        ('post_entities_alerts_v1', {'ids': ids}),
    ]
    for name, kwargs in candidates:
        if hasattr(alerts_client, name):
            logging.info("Using Alerts.%s", name)
            func = getattr(alerts_client, name)
            try:
                resp = func(**kwargs)
            except TypeError:
                # try passing kwargs inside a body key
                try:
                    resp = func(body=kwargs)
                except Exception as e:
                    logging.debug("Failed calling %s: %s", name, e)
                    continue
            body = resp.get('body', {}) if isinstance(resp, dict) else {}
            # try to extract entity list
            if isinstance(body, dict):
                if 'resources' in body and isinstance(body['resources'], list):
                    return body['resources']
                if 'entities' in body and isinstance(body['entities'], list):
                    return body['entities']
            # sometimes the response is list directly
            if isinstance(resp, list):
                return resp
    logging.warning("Could not fetch alert entities via known methods")
    return []

def get_crowdstrike_alerts(filter_str=None, limit=200):
    """
    Authenticate and fetch alert entities (full JSON objects) from Falcon Alerts API.
    """
    if not (FALCON_CLIENT_ID and FALCON_CLIENT_SECRET):
        logging.error('CrowdStrike credentials missing; skipping alert pull')
        return []

    alerts_client = Alerts(client_id=FALCON_CLIENT_ID, client_secret=FALCON_CLIENT_SECRET)
    ids = get_alert_ids(alerts_client, filter_str=filter_str, limit=limit)
    logging.info("Found %d alert ids/composite ids", len(ids))
    entities = fetch_alert_entities(alerts_client, ids)
    logging.info("Fetched %d alert entities", len(entities))
    return entities

def main_once():
    # Example filter: new alerts in the last 7 days (you can change per your needs)
    filter_str = None  # e.g., \"status:'new'\"\n
    alerts = get_crowdstrike_alerts(filter_str=filter_str, limit=200)
    for alert in alerts:
        hashes = recursive_find_hashes(alert)
        logging.info('Alert -> found %d hashes', len(hashes))
        for h in hashes:
            if es.exists(index=args.index, id=h):
                logging.info('Hash %s already indexed; skipping VT', h)
                continue
            vt = vt_lookup(h)
            doc = {
                'alert': alert.get('id') or alert.get('alert_id') or None,
                'timestamp': int(time.time()*1000),
                'hash': h,
                'crowdstrike_alert': alert,
                'virustotal': vt
            }
            index_doc(doc)
            logging.info('Indexed hash %s', h)
            time.sleep(1)

if __name__ == '__main__':
    main_once()
