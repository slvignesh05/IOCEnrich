#!/usr/bin/env python3
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
es.index(index=index, id=doc.get('hash'), pipeline='vt_extract', body=doc)




def get_crowdstrike_detects():
if not FALCON_CLIENT_ID or not FALCON_CLIENT_SECRET:
logging.error('CrowdStrike credentials missing; skipping CrowdStrike pull')
return []
detects = Detects(client_id=FALCON_CLIENT_ID, client_secret=FALCON_CLIENT_SECRET)
# use a simple time-window; you can customize filters
r = detects.query_detects() # returns list of detect ids
resources = r.get('body', {}).get('resources', [])
return resources




def get_detect_summary(detect_id):
detects = Detects(client_id=FALCON_CLIENT_ID, client_secret=FALCON_CLIENT_SECRET)
r = detects.get_detect_summaries(ids=detect_id)
return r.get('body', {})




def main_once():
resources = get_crowdstrike_detects()
logging.info('Found %d detects', len(resources))
for detect_id in resources:
det = get_detect_summary(detect_id)
hashes = recursive_find_hashes(det)
logging.info('Detect %s -> found %d hashes', detect_id, len(hashes))
for h in hashes:
# check if already in ES
if es.exists(index=args.index, id=h):
logging.info('Hash %s already indexed; skipping VT', h)
continue
vt = vt_lookup(h)
doc = {
'detection_id': detect_id,
'timestamp': int(time.time()*1000),
'hash': h,
'crowdstrike_detection': det,
'virustotal': vt
}
index_doc(doc)
logging.info('Indexed hash %s', h)
time.sleep(1)


if __name__ == '__main__':
main_once()
