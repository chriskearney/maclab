#!/usr/bin/env python3
"""Pure data adapter for genuine fresh capture/retention/fetch phase outputs.
No transport; retained sources are byte candidates, never completion evidence.
"""
import argparse,base64,hashlib,json,re
from pathlib import Path
M5='/Users/chriskearney/.local/share/maclab/recovery-retained'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(v):return hashlib.sha256(v).hexdigest()
def receipt(c,packet,boot):
 raw=base64.b64decode(c['receipt_base64'],validate=True);need(len(raw)<=262144 and H(raw)==c['receipt_sha256'],'genuine raw capture hash');r=json.loads(raw);need(r==c['receipt'] and r['packet']==packet and r['boot_id']==boot and r['device']=='m1','raw/decoded/current capture mismatch');return r

def make(b):
 p=b['profile'];packet=p['packet'];plan=b['root_plan_sha256'];need(p['device']=='m1' and re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}',packet) and re.fullmatch('[0-9a-f]{64}',plan),'fresh packet/actual plan required');mode=b['operation'];root=M5+'/'+Path(packet).name
 if mode=='fetch':
  r=b['retention_result'];kind=b['mode'];need(kind in ('main','supplement') and r['status']=='INDEPENDENT_REMOTE_RETENTION_VERIFIED' and r['historical_completion_reused'] is False,'actual successful retention output required');path=root+('/MIRROR-RECEIPT.json' if kind=='main' else '/supplement/RETENTION-RECEIPT.json');need(r['receipt_path']==path and re.fullmatch('[0-9a-f]{64}',r['receipt_sha256']) and type(r['receipt_bytes']) is int and 0<r['receipt_bytes']<=262144,'exact newly retained receipt')
  need(type(b['storage_dev']) is int and b['storage_dev']>0,'reviewed actual M5 storage required');return {'schema':'maclab.m5-receipt-fetch/1','packet':packet,'root_plan_sha256':plan,'receipt_path':path,'receipt_sha256':r['receipt_sha256'],'receipt_bytes':r['receipt_bytes'],'storage_dev':b['storage_dev']}
 need(mode in ('main','supplement'),'finite retention binding mode');boot=b['boot_id'];c=b['main_capture'];r=receipt(c,packet,boot);need(r['schema']=='maclab.rc-m1-original-backup/1' and r['status']=='LOCAL_BACKUP_VERIFIED_ONLY' and r['script_sha256']==p['backup_source']['sha256'],'actual reviewed main capture required')
 candidates={};storage=None
 for value in b['retained_candidate_receipts']:
  # These receipts are explicitly pinned recipe inputs. Every candidate byte
  # is independently reopened/rehashed by the existing M5 core before reuse.
  raw=base64.b64decode(value['raw_base64'],validate=True);need(H(raw)==value['sha256'],'retained candidate receipt source drift');old=json.loads(raw);need(old['status']=='INDEPENDENT_REMOTE_RETENTION_VERIFIED' and old['device']=='m1' and old['destination']['device']=='m5' and old['destination']['storage']['os']=='darwin','actual M5 candidate provenance required')
  dev=old['destination']['storage']['storage_dev'];need(storage is None or storage==dev,'M5 candidate storage changed');storage=dev
  for group,rows in old['groups'].items():
   need(group in ('main','supplement'),'unknown retained group')
   for name,pin in rows.items():
    if name.endswith('RECEIPT.json'):continue
    path=pin['remote_path'];need(path.startswith(M5+'/') and Path(path).name==name and pin['remote_fsync_reopen_match'] is True,'typed actual retained byte source');item={k:pin[k] for k in ('sha256','bytes')};item['path']=path
    if item not in candidates.setdefault(name,[]):candidates[name].append(item)
 def objects(r):return {name:{'sha256':pin['sha256'],'bytes':pin['bytes'],'allowed_retained_sources':candidates.get(name,[])} for name,pin in r['objects'].items()}
 q={'schema':'maclab.retention-reuse-request/1','root_plan_sha256':plan,'source_freeze_sha256':c['source_freeze_sha256'],'source':{'device':'m1','packet':packet,'boot_id':boot,'target_backup_receipt_sha256':c['receipt_sha256'],'target_backup_receipt':r},'destination':root,'objects':objects(r)}
 if mode=='supplement':
  sc=b['supplement_capture'];sr=receipt(sc,packet,boot);need(sr['v1_target_receipt_sha256']==c['receipt_sha256'] and sr['status']=='LOCAL_SUPPLEMENT_VERIFIED_ONLY' and sr['supplement_script_sha256']==p['supplement_source']['sha256'],'same fresh main/supplement source required');f=b['actual_main_retention'];need(f['status']=='ACTUAL_M5_RECEIPT_FETCHED','actual new parent receipt fetch required');pr=base64.b64decode(f['observed']['raw_base64'],validate=True);ph=H(pr);parent=json.loads(pr);need(parent==f['receipt'] and parent['packet']==packet and parent['root_plan_sha256']==plan and parent['boot_id']==boot and parent['v1_target_receipt_sha256']==c['receipt_sha256'] and set(parent['groups'])=={'main'},'actual parent main receipt raw/identity mismatch');q['supplement']={'target_receipt_sha256':sc['receipt_sha256'],'target_receipt':sr,'objects':objects(sr),'parent_main_receipt_sha256':ph,'parent_main_receipt':parent}
 need(type(storage) is int and storage>0,'reviewed M5 actual-volume source required');return {'mode':mode,'root_plan_sha256':plan,'source_holder':p['holder'],'request':q,'reviewed_m5_storage_dev':storage}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(make(json.loads(x.binding.read_bytes())),separators=(',',':')))
