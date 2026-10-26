package workflow

// This optional adapter runs only in the standalone client process. It changes
// no server/agent policy and never treats a retained phase output as current
// technical recovery readiness. The generic Backend.Submit path is unchanged.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iconidentify/maclab/internal/api"
	"github.com/iconidentify/maclab/internal/client"
)

type M1SubmissionAdmission struct {
	BootID          Value `json:"boot_id"`
	AgentSHA256     Value `json:"agent_sha256"`
	MinimumLeaseSec int   `json:"minimum_lease_sec"`
}
type M1AdmittingBackend interface {
	SubmitM1(context.Context, api.JobSpec, string, int, string) (*api.Job, error)
}
type M1SubmissionClient interface {
	Submit(context.Context, api.JobSpec) (*api.Job, error)
	Device(context.Context, string) (*client.Device, error)
	OOBStatus(context.Context, string) (map[string]any, error)
	Exec(context.Context, string, api.ExecArgs) (*api.ExecResult, error)
}

// M1Backend embeds the existing authenticated client for uploads/job reads.
// The explicit per-submit admission calls SubmitM1, not the generic method.
type M1Backend struct {
	Backend
	Client M1SubmissionClient
	Now    func() time.Time
}

// The legacy field/probe schema names cover exactly these two M1-family boards.
func m1FamilyIdentity(device string) (board, model string, ok bool) {
	switch device {
	case "m1":
		return "apple,j293", "Apple MacBook Pro (13-inch, M1, 2020)", true
	case "m1air":
		return "apple,j313", "Apple MacBook Air (M1, 2020)", true
	default:
		return "", "", false
	}
}

func (b *M1Backend) SubmitM1(ctx context.Context, spec api.JobSpec, boot string, minimum int, agentSHA string) (*api.Job, error) {
	board, model, supported := m1FamilyIdentity(spec.Device)
	if !api.ValidRecoveryMode(spec.RecoveryMode) || !supported || spec.Holder == "" || spec.InstalledManifest == "" || minimum < 2700 || minimum > 7200 || boot == "" || !shaRE.MatchString(agentSHA) {
		return nil, errors.New("invalid reviewed M1 installed submission admission")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	check := func(d *client.Device) error {
		if d == nil || d.Name != spec.Device || d.State != api.StateReady || !d.Alive || d.ActiveJob != "" || d.Queued != 0 || d.BootID != boot || d.Kernel != "7.2.11-6-1-ARCH" || strings.Contains(d.Cmdline, "maclab.job=") {
			return errors.New("M1 submit-time ordinary boot/readiness drift")
		}
		modelOK := len(d.Facts.Compatible) > 0 && d.Facts.Compatible[0] == board
		if len(d.Facts.Compatible) == 0 {
			modelOK = d.Facts.DTModel == model
		}
		requiredTier := 2
		if spec.RecoveryMode == api.RecoveryNetworkOnly {
			requiredTier = 1
		}
		if d.Facts.Machine != "aarch64" || !modelOK || d.Tier < requiredTier {
			return errors.New("M1 submit-time model/recovery tier mismatch")
		}
		if spec.RecoveryMode == api.RecoveryNetworkOnly && (d.KnownGood != d.Kernel || !d.Facts.PreflightOK || !d.Facts.Watchdog || !d.Facts.WatchdogArmed || d.Facts.PanicTimeout <= 0) {
			return errors.New("M1 network-only one-shot/panic/watchdog/known-good preflight facts are not ready")
		}
		if spec.Device == "m1air" && (spec.RecoveryTransaction == "" || d.EffectiveRecoveryMode != spec.RecoveryMode || d.RecoveryTransaction != spec.RecoveryTransaction || d.RecoveryHolder != spec.Holder) {
			return errors.New("Air submit-time recovery transaction drift")
		}
		if d.Lease == nil || d.Lease.Holder != spec.Holder || d.Lease.Expires.Sub(now()) < time.Duration(minimum)*time.Second {
			return errors.New("M1 submit-time lease does not cover job and cleanup")
		}
		return nil
	}
	d, err := b.Client.Device(ctx, spec.Device)
	if err != nil {
		return nil, err
	}
	if err = check(d); err != nil {
		return nil, err
	}
	if spec.RecoveryMode != api.RecoveryNetworkOnly {
		oob, err := b.Client.OOBStatus(ctx, spec.Device)
		if err != nil {
			return nil, fmt.Errorf("M1 live recovery route: %w", err)
		}
		controller, cok := oob["controller"].(string)
		status, sok := oob["status"].(string)
		failure := oob["error"]
		if !cok || !strings.HasPrefix(controller, "oobd ") || !sok || strings.TrimSpace(status) == "" || (failure != nil && failure != "") {
			return nil, errors.New("M1 live OOB route is unhealthy; no job submitted")
		}
	}
	// The actual direct-agent process probes all four markers immediately before
	// the second device read and POST. A retained prior helper receipt cannot
	// replace this request; serial fallback fails before the probe can read devices.
	if err := b.probeM1Markers(ctx, spec.Device, board, boot, agentSHA); err != nil {
		return nil, err
	}
	// A slow status call or a boot/lease change during it cannot authorize POST.
	d, err = b.Client.Device(ctx, spec.Device)
	if err != nil {
		return nil, err
	}
	if err = check(d); err != nil {
		return nil, err
	}
	if now().Sub(start) > 20*time.Second {
		return nil, errors.New("M1 technical observation exceeded freshness bound; no job submitted")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return b.Client.Submit(ctx, spec)
}

// Read-only fixed probe. The agent's /exec currently accepts one shell string;
// fixed interpreter/source plus properly single-quoted JSON data is intentional.
func m1ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (b *M1Backend) probeM1Markers(ctx context.Context, device, board, boot, agentSHA string) error {
	pin, _ := json.Marshal(map[string]string{"boot_id": boot, "agent_sha256": agentSHA, "device": device})
	command := "/usr/bin/python3 -E -c " + m1ShellQuote(m1MarkerProbe) + " " + m1ShellQuote(string(pin))
	r, err := b.Client.Exec(ctx, device, api.ExecArgs{Command: command, TimeoutSec: 15})
	if err != nil {
		return errors.New("M1 submit-time marker probe transport failed; no job submitted")
	}
	if r == nil || r.Via != "agent" || r.ExitCode != 0 || r.Stderr != "" || len(r.Stdout) > 4096 {
		return errors.New("M1 submit-time marker probe failed; no job submitted")
	}
	var v struct {
		Schema          string          `json:"schema"`
		Status          string          `json:"status"`
		Device          string          `json:"device"`
		BootID          string          `json:"boot_id"`
		Kernel          string          `json:"kernel"`
		Board           string          `json:"board"`
		AgentPath       string          `json:"agent_path"`
		AgentSHA        string          `json:"agent_sha256"`
		Markers         map[string]bool `json:"markers"`
		TargetMutations *bool           `json:"target_mutations"`
	}
	if err = Decode([]byte(r.Stdout), &v); err != nil {
		return errors.New("M1 marker reply is not exact typed JSON")
	}
	if v.Schema != "maclab.m1-submit-markers/1" || v.Status != "ALL_FOUR_MARKERS_ABSENT" || v.Device != device || v.BootID != boot || v.Kernel != "7.2.11-6-1-ARCH" || v.Board != board || v.AgentPath != "/usr/local/bin/lab-agent" || v.AgentSHA != agentSHA || v.TargetMutations == nil || *v.TargetMutations || len(v.Markers) != 4 {
		return errors.New("M1 marker reply identity drift")
	}
	for _, kernel := range []string{"7.2.11-6-1-ARCH", "7.2.11-7-1-ARCH"} {
		for _, leaf := range []string{".maclab-job", ".maclab-owned"} {
			absent, ok := v.Markers["/usr/lib/modules/"+kernel+"/"+leaf]
			if !ok || !absent {
				return errors.New("M1 module marker exists or is unproved")
			}
		}
	}
	return nil
}

const m1MarkerProbe = `import hashlib,json,os,stat,sys

def need(ok):
 if not ok:raise RuntimeError('M1 submit-marker admission refused')
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def small(path,limit):
 fd=os.open(path,os.O_PATH|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode));rd=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   data=os.pread(rd,limit+1,0);need(len(data)<=limit and identity(os.fstat(rd))==identity(s));return data
  finally:os.close(rd)
 finally:os.close(fd)
def birth(pid):return small('/proc/'+str(pid)+'/stat',32768).rsplit(b')',1)[1].split()[19]
def agent(pin):
 pid=os.getppid();before=birth(pid);proc='/proc/'+str(pid)+'/exe';path='/usr/local/bin/lab-agent';need(os.readlink(proc)==path)
 held=os.open(proc,os.O_PATH|os.O_CLOEXEC);live=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(held);need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022 and 0<s.st_size<=67108864 and identity(s)==identity(os.fstat(live)))
  rd=os.open('/proc/self/fd/'+str(held),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   h=hashlib.sha256();offset=0
   while offset<s.st_size:
    block=os.pread(rd,min(1048576,s.st_size-offset),offset);need(bool(block));h.update(block);offset+=len(block)
   need(not os.pread(rd,1,offset) and h.hexdigest()==pin['agent_sha256'] and identity(os.fstat(rd))==identity(s))
  finally:os.close(rd)
  need(os.getppid()==pid and before==birth(pid) and os.readlink(proc)==path and identity(os.stat(proc))==identity(s) and identity(os.lstat(path))==identity(s))
 finally:os.close(live);os.close(held)
def markers():
 out={}
 for kernel in ('7.2.11-6-1-ARCH','7.2.11-7-1-ARCH'):
  for name in ('.maclab-job','.maclab-owned'):
   path='/usr/lib/modules/'+kernel+'/'+name
   try:os.lstat(path)
   except FileNotFoundError:out[path]=True
   else:raise RuntimeError('M1 module marker is present')
 return out
def run(pin):
 need(os.geteuid()==0);agent(pin)
 device=pin.get('device','m1');boards={'m1':'apple,j293','m1air':'apple,j313'};need(device in boards);board=boards[device]
 def current():
  need(small('/proc/sys/kernel/random/boot_id',128).decode().strip()==pin['boot_id'] and os.uname().release=='7.2.11-6-1-ARCH' and small('/proc/device-tree/compatible',4096).split(b'\0')[0]==board.encode() and b'maclab.job=' not in small('/proc/cmdline',32768))
 current();out=markers();current();agent(pin)
 return {'schema':'maclab.m1-submit-markers/1','status':'ALL_FOUR_MARKERS_ABSENT','device':device,'boot_id':pin['boot_id'],'kernel':'7.2.11-6-1-ARCH','board':board,'agent_path':'/usr/local/bin/lab-agent','agent_sha256':pin['agent_sha256'],'markers':out,'target_mutations':False}
if __name__=='__main__':
 try:print(json.dumps(run(json.loads(sys.argv[1])),separators=(',',':')))
 except Exception:print('M1 submit-marker admission refused',file=sys.stderr);sys.exit(1)
`
