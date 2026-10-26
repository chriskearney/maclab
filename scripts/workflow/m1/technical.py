#!/usr/bin/env python3
"""Fresh read-only technical observations for the finite M1 package producer.
Returns explicit safe projections, never the device's OOB credentials. Standing
user authorization is separate; this source supplies no manual confirmations.
"""
import argparse,datetime,hashlib,json,re,time
from pathlib import Path
SDK='d5e4a7cc72c2bffaf9fdbe7e44a56ac50486f9cb47fcb28aee047d292919094a'
def need(v,msg):
 if not v:raise RuntimeError(msg)
def H(b):return hashlib.sha256(b).hexdigest()
def sdk():
 import sys
 p=Path(__file__).with_name('frozen-controller-ea3.py');raw=p.read_bytes();need(H(raw)==SDK,'accepted transport drift');m=type(sys)('readiness_transport');exec(compile(raw,str(p),'exec'),m.__dict__);return m
def observe(b,api=None,now=None,monotonic=None):
 c=sdk();p=b['profile'];need(p['device']=='m1' and p['board']=='apple,j293' and re.fullmatch('/var/lib/maclab/rc7-m1-[a-z0-9-]{8,96}',p['packet']),'finite M1 packet/model');need(re.fullmatch('[0-9a-f]{64}',b['root_plan_sha256']),'actual root plan');need(b['expected_kernel'] in ('7.2.11-6-1-ARCH','7.2.11-7-1-ARCH'),'normal cohort kernel only');minimum=b['minimum_lease_seconds'];need(type(minimum) is int and 1990<=minimum<=7200,'package/cleanup lease budget')
 client=api or c.API(c.config());clock=now or (lambda:datetime.datetime.now(datetime.timezone.utc));mono=monotonic or time.monotonic;deadline=mono()+20
 def request(path):
  remaining=deadline-mono();need(remaining>0,'technical request deadline exceeded');return client.request(path,timeout=min(10,remaining))
 start=clock();d=request('/api/devices/m1');c.state_gate(d,p,b,True,minimum)
 need(d.get('tier',0)>=2 and d['facts']['machine']=='aarch64' and d['facts']['compatible'][0]=='apple,j293' and 'maclab.job=' not in d['cmdline'],'actual normal M1 recovery model')
 o=request('/api/devices/m1/oob');oob_time=clock();need(not o.get('error') and isinstance(o.get('controller'),str) and o['controller'].startswith('oobd ') and isinstance(o.get('status'),str) and o['status'].strip(),'M1 live OOB route unhealthy; no mutation or job submitted')
 # Re-read the ordinary identity/lease after the live recovery request.
 d2=request('/api/devices/m1');c.state_gate(d2,p,b,True,minimum);need(d2['facts']['machine']=='aarch64' and d2['facts']['compatible'][0]=='apple,j293' and d2.get('tier',0)>=2 and 'maclab.job=' not in d2['cmdline'],'model/ordinary boot changed during technical observation');end=clock();need(mono()<=deadline and 0<=(end-start).total_seconds()<=20,'technical observation exceeded freshness bound')
 safe={k:d2.get(k) for k in ('name','state','alive','active_job','queued','boot_id','kernel','cmdline','tier')};safe['lease']={k:d2['lease'][k] for k in ('holder','expires')};safe['facts']={k:d2['facts'].get(k) for k in ('machine','compatible')};oob={k:o[k] for k in ('controller','status','serial_connected','serial_last') if k in o};timestamp=end.isoformat()
 return {'status':'FRESH_M1_TECHNICAL_READINESS_OBSERVED','packet':p['packet'],'root_plan_sha256':b['root_plan_sha256'],'expected_boot_id':b['expected_boot_id'],'source_sha256':H(Path(__file__).read_bytes()),'technical':{'device':{'observed_utc':timestamp,'value':safe},'oob':{'observed_utc':oob_time.isoformat(),'value':oob}},'manual_saved_work_confirmed':False,'manual_nearby_recovery_confirmed':False,'no_target_or_reference_mutations':True,'job_submitted':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(observe(json.loads(x.binding.read_bytes())),separators=(',',':')))
