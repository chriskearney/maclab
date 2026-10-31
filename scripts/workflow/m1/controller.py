#!/usr/bin/env python3
"""Reviewed fixed-protocol M1 workflow transport over existing Maclab admin API.
No new daemon, SSH credentials, arbitrary command template, or package installer.
"""
import argparse,base64,datetime,hashlib,json,os,shlex,stat,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path

LIMIT=4*1024**2
ALLOWED={'inventory-cache','stage-cache','invoke-packet','stage-backup-inputs','capture-original','collect-backup','stage-supplement-inputs','capture-supplement','collect-supplement','collect-closure'}

# >>> maclab-labhttp v1 (canonical: tools/bt2/bt2/labhttp.py) >>>
import ipaddress as _lh_ip
import ssl as _lh_ssl
import urllib.parse as _lh_parse
import urllib.request as _lh_req


class TransportRefused(RuntimeError):
    """The request broke the labd client transport policy: it was not sent, or a redirect was not followed."""


def _lh_loopback(host):
    if host == 'localhost':
        return True
    try:
        return _lh_ip.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url, allow_plain_http=False):
    """Refuse a URL a bearer token must not be sent to. Returns its scheme."""
    u = _lh_parse.urlsplit(url)
    if u.scheme not in ('https', 'http') or not u.hostname or u.username is not None or u.password is not None:
        raise TransportRefused('labd URL %r: give https://host[:port] (no credentials in the URL)' % (url,))
    if u.scheme == 'http' and not _lh_loopback(u.hostname) and not allow_plain_http:
        raise TransportRefused('labd URL %s is plain http to %s, which is not loopback: use https, or opt in to plain http '
                               'explicitly (MACLAB_ALLOW_PLAIN_HTTP=1, or "allow_plain_http": true in the config)'
                               % (url, u.hostname))
    return u.scheme


class _LhGuard(_lh_req.BaseHandler):
    handler_order = 100  # before anything is sent

    def __init__(self, allow_plain_http):
        self.allow_plain_http = allow_plain_http

    def http_request(self, req):
        check_url(req.full_url, self.allow_plain_http)
        return req

    https_request = http_request


class _LhNoRedirect(_lh_req.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise TransportRefused('labd answered %d with a redirect to %s; redirects are never followed' % (code, newurl))


def tls_context(ca_file=None, ca_pem=None):
    """System roots plus an optional private CA (a PEM file, or PEM text). Verification always on."""
    ctx = _lh_ssl.create_default_context()
    ctx.minimum_version = _lh_ssl.TLSVersion.TLSv1_2
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if ca_pem:
        if not isinstance(ca_pem, str) or '-----BEGIN CERTIFICATE-----' not in ca_pem:
            raise TransportRefused('server_ca is not PEM certificate text')
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def opener(url, allow_plain_http=False, ca_file=None, ca_pem=None):
    """An opener for labd at url: refuses the URL now if it breaks the policy, and checks every request it sends."""
    check_url(url, allow_plain_http)
    o = _lh_req.OpenerDirector()
    for h in (_LhGuard(allow_plain_http), _lh_req.HTTPHandler(), _lh_req.HTTPSHandler(context=tls_context(ca_file, ca_pem)),
              _LhNoRedirect(), _lh_req.HTTPDefaultErrorHandler(), _lh_req.HTTPErrorProcessor(), _lh_req.UnknownHandler()):
        o.add_handler(h)
    return o


def maintainer_policy(config, environ):
    """A Maintainer tool's choices, from MACLAB_CA_FILE / MACLAB_ALLOW_PLAIN_HTTP=1, else client.json's
    "ca_file" / "allow_plain_http": true. Plain http to a non-loopback host needs one of the two opt-ins."""
    ca_file = environ.get('MACLAB_CA_FILE') or config.get('ca_file') or None
    allow = environ.get('MACLAB_ALLOW_PLAIN_HTTP') == '1' or config.get('allow_plain_http') is True
    return {'allow_plain_http': allow, 'ca_file': ca_file}


def agent_policy(agent):
    """A Mac's choices, from /etc/maclab/agent.json, the same rule as lab-agent: "server_ca" is PEM text;
    "allow_plain_http": true opts in, false refuses, and an agent.json without the key (written by an older lab-agent)
    keeps plain http with a warning. Returns (policy, warning or None)."""
    warning = None
    if 'allow_plain_http' in agent:
        if not isinstance(agent['allow_plain_http'], bool):
            raise TransportRefused('agent.json allow_plain_http must be true or false')
        allow = agent['allow_plain_http']
    else:
        allow = True
        u = _lh_parse.urlsplit(agent.get('server') or '')
        if u.scheme == 'http' and not _lh_loopback(u.hostname or ''):
            warning = ('agent.json has no allow_plain_http (an older lab-agent wrote it), so plain http to %s is allowed '
                       'as before; run lab-agent setup again with --ca-file or --allow-plain-http to decide' % u.hostname)
    return {'allow_plain_http': allow, 'ca_pem': agent.get('server_ca') or None}, warning
# <<< maclab-labhttp v1 <<<

def need(v,msg):
 if not v:raise RuntimeError(msg)
def read_pin(pin):
 p=Path(pin['path']);fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(stat.S_ISREG(a.st_mode) and a.st_size==pin['bytes']<=LIMIT,'not bounded source')
  f=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   b=os.read(f,a.st_size+1);need(len(b)==a.st_size and key(os.fstat(f))==key(a)==key(p.lstat()),'source inode drift')
  finally:os.close(f)
  need(hashlib.sha256(b).hexdigest()==pin['sha256'],'source hash drift');return b
 finally:os.close(fd)
def config():
 path=Path(os.environ.get('XDG_CONFIG_HOME',str(Path.home()/'.config')))/'maclab/client.json';c=json.loads(path.read_bytes());c['url']=os.environ.get('MACLAB_URL',c['url']).rstrip('/');c['token']=os.environ.get('MACLAB_TOKEN',c['token']);u=urllib.parse.urlsplit(c['url']);need(u.scheme in ('http','https') and u.hostname and not u.username and not u.password,'unsafe configured endpoint');return c
class API:
 def __init__(self,c):self.c=c;self.o=opener(c['url'],**maintainer_policy(c,os.environ))  # docs/https.md transport policy
 def request(self,path,body=None,timeout=60):
  req=urllib.request.Request(self.c['url']+path,data=None if body is None else json.dumps(body,separators=(',',':')).encode(),headers={'Authorization':'Bearer '+self.c['token'],'Content-Type':'application/json'})
  with self.o.open(req,timeout=timeout) as response:raw=response.read(LIMIT+1)
  need(len(raw)<=LIMIT,'API response exceeds bound');return json.loads(raw)
def state_gate(d,p,binding,mutates,minimum_seconds=0):
 need(d['name']==p['device'] and d['state']=='ready' and d['alive'] and not d.get('active_job') and not d.get('queued'),'Mac is not genuinely ready/idle')
 need(d['kernel']==binding['expected_kernel'] and d['boot_id']==binding['expected_boot_id'],'fresh live controller identity drift')
 if mutates:
  lease=d.get('lease',{});need(lease.get('holder')==p['holder'],'exclusive coordinator lease required')
  expires=datetime.datetime.fromisoformat(lease['expires'].replace('Z','+00:00'));need(expires.tzinfo is not None and (expires-datetime.datetime.now(datetime.timezone.utc)).total_seconds()>=minimum_seconds,'lease would expire inside phase/cleanup; renew existing lease, no new user permission')
 return d

def write_capture(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(raw)<=LIMIT,'private capture ceiling')
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:n=os.write(fd,view);need(n>0,'short capture write');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 st=path.lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600,'private capture ownership/mode');need(read_pin({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})==raw,'private capture readback mismatch');d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(d)
 finally:os.close(d)
 return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'independent_retention_claim':False}

def run_closure(binding,api=None):
 p=binding['profile'];pin=p['closure_collector'];source=read_pin(pin);need(source==Path(__file__).with_name('closure-collector.py').read_bytes(),'reviewed collector closure mismatch')
 c=api or API(config());d=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe=''));bound=dict(binding)
 if bound.get('expected_boot_id') is None:bound['expected_boot_id']=d['boot_id']
 state_gate(d,p,bound,False)
 # Source is fixed/pinned. All three pacman-conf calls are literal read-only
 # queries; no hook command or captured text is ever executed.
 remote="import base64,contextlib,io,json,subprocess\nsource=base64.b64decode("+repr(base64.b64encode(source).decode())+",validate=True);buf=io.StringIO();ns={'__name__':'reviewed_closure'}\nwith contextlib.redirect_stdout(buf):\n exec(compile(source,'<reviewed-readonly-collector>','exec'),ns);ns['main']()\nconf={}\nfor key in ['HookDir','NoExtract','NoUpgrade']:\n p=subprocess.run(['/usr/bin/pacman-conf',key],capture_output=True,text=True,timeout=10);conf[key]={'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}\nprint(json.dumps({'collector_stdout':buf.getvalue(),'pacman_conf':conf},separators=(',',':')))"
 command=shlex.join(['/usr/bin/python3','-E','-B','-c',remote]);need(len(command.encode())<=120000,'fixed closure transport ceiling')
 result=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe='')+'/exec',{'command':command,'timeout_sec':180},270)
 capture=write_capture(Path(__file__).parent/'closure-api-capture.json',{'schema':'maclab.m1-closure-api-capture/1','collector_source_sha256':pin['sha256'],'actual_exec':result,'controller_boot_id':d['boot_id']})
 if result['exit_code']!=0 or result.get('via')!='agent':return {'status':'M1_CLOSURE_CAPTURE_FAILED','capture':capture,'device':p['device'],'boot_id':d['boot_id']}
 envelope=json.loads(result['stdout']);actual=json.loads(envelope['collector_stdout']);need(actual['boot_id']==d['boot_id'] and actual['kernel']==bound['expected_kernel'] and actual['board']==p['board'],'closure collector actual identity mismatch')
 return {'status':'M1_CLOSURE_OBSERVED','capture':capture,'collector_source_sha256':pin['sha256'],'device':p['device'],'boot_id':actual['boot_id'],'kernel':actual['kernel'],'board':actual['board'],'collector_status':actual['status'],'STOP':actual['STOP'],'old_module_tree_sha256':actual['old_module_tree_sha256'],'hook_source_count':len(actual['all_vendor_and_local_hook_sources']),'closure_file_count':len(actual['closure_files']),'fallback_config_directories':actual['fallback_config_directories'],'pacman_conf':envelope['pacman_conf'],'readiness_claim':False,'independent_retention_claim':False}

def run(binding,api=None):
 p=binding['profile'];action=binding['action'];need(action in ALLOWED,'unknown typed M1 operation')
 if action=='collect-closure':return run_closure(binding,api)
 # Structural target validation also runs before the RPC, from the exact source
 # closure; do not dynamically import arbitrary plan modules.
 pin=p['target_adapter'];need(Path(pin['path']).name=='target.py','fixed target adapter basename required');source=read_pin(pin)
 need(source==Path(__file__).with_name('target.py').read_bytes(),'controller/target closure mismatch')
 c=api or API(config());mutates=action not in ('inventory-cache','collect-backup','collect-supplement');d=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe=''));binding=dict(binding)
 if not mutates and binding.get('expected_boot_id') is None:binding['expected_boot_id']=d['boot_id']
 state_gate(d,p,binding,mutates,int(binding['deadline_seconds'])+90)
 payload={k:binding[k] for k in ('action','profile','expected_boot_id','expected_kernel','deadline_seconds')}
 for extra in ['entry','prepared_inputs','receipt_sha256']:
  if extra in binding:payload[extra]=binding[extra]
 if mutates:
  authority=read_pin(p['authority_source']);a=json.loads(authority)
  need(a['authorization_is_persistent'] is True and a['manual_saved_work_confirmed'] is False and a['manual_nearby_recovery_confirmed'] is False and a['does_not_lift_existing_holds'] is True,'standing authority facts mismatch')
  scope=binding['root_scope'];need(scope['packet']==p['packet'] and scope['device']==p['device'] and scope['expected_boot_id']==binding['expected_boot_id'] and action in scope['operations'] and scope['authority_sha256']==p['authority_source']['sha256'],'root scope is not bound to this fresh packet/boot/operation')
  need(scope['reviewed_by'] and scope['manual_saved_work_confirmed'] is False and scope['manual_nearby_recovery_confirmed'] is False,'do not invent confirmations')
  payload['standing_authority_b64']=base64.b64encode(authority).decode();payload['root_scope']=scope
 # Exactly one logged existing exec call. Source and JSON are individually
 # quoted arguments; no profile data is evaluated as source or shell syntax.
 argv=['/usr/bin/python3','-E','-B','-c',source.decode(),'--request-json',json.dumps(payload,separators=(',',':'))]
 command=shlex.join(argv);need(len(command.encode())<=120000,'fixed transport ceiling exceeded')
 timeout=int(binding['deadline_seconds']);need(1<=timeout<=1900,'bounded phase timeout required')
 if action=='invoke-packet':need(timeout==1900,'owner/PacketC requires complete1900-second outer cleanup envelope')
 elif action=='capture-original':need(timeout==1200,'full900s capture and cleanup requires1200s envelope')
 else:need(timeout<=900,'metadata/cache deadline ceiling')
 result=c.request('/api/devices/'+urllib.parse.quote(p['device'],safe='')+'/exec',{'command':command,'timeout_sec':timeout+60},timeout+90)
 if result['exit_code']!=0 or result.get('via')!='agent':return {'status':'M1_TARGET_FAILED','device':p['device'],'boot_id':d['boot_id'],'actual_exec':result,'source_sha256':pin['sha256']}
 # Preserve the authentic full API receipt in caller stdout for the workflow
 # journal; a success status is never synthesized from missing target evidence.
 out={'status':'OWNER_EXIT_ONLY_REQUIRES_INDEPENDENT_RECEIPT_VALIDATION','exit_code':result['exit_code'],'completion_claim':False} if action=='invoke-packet' else json.loads(result['stdout']);need(isinstance(out,dict),'target result is not an object')
 envelope={'status':'M1_'+action.upper().replace('-','_')+'_OBSERVED','device':p['device'],'boot_id':d['boot_id'],'kernel':d['kernel'],'actual_exec':result,'target':out,'source_sha256':pin['sha256'],'controller_state':{k:d.get(k) for k in ['name','state','alive','boot_id','kernel','lease','active_job','queued']},'no_new_user_confirmation':True}
 if action=='collect-backup':
  captured=write_capture(Path(__file__).parent/'collect-backup-envelope.json',envelope);envelope['envelope']={k:captured[k] for k in ('path','sha256','bytes')}
 return envelope
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--binding',type=Path,required=True);x=a.parse_args();print(json.dumps(run(json.loads(x.binding.read_bytes())),separators=(',',':')))
