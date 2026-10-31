# labd over HTTPS, without Tailscale

labd can run as a plain HTTPS service. Maintainers use the web UI, `lab` and its MCP server over HTTPS. Macs reach labd with
outbound requests only: check-in long polls, reports, uploads, and artifact downloads with resume. There are no WebSockets,
and nothing connects *to* a Mac. Tailscale still works as before, but nothing here needs it.

The main deployment is a Kubernetes workload at **https://chonkbase.net/maclab**, replacing slopblender's place on that host.
A reverse proxy or labd's own TLS work too (see [Other ways to serve HTTPS](#other-ways-to-serve-https)).

## labd's flags for HTTPS

| flag | what it does |
|---|---|
| `--public-url https://host[:port][/path]` | The one external URL. labd serves everything under its path, removing the path exactly once, and builds browser and enrollment URLs from it. Without it, labd serves at `/` |
| `--trusted-proxy CIDR[,CIDR]` | The only peers whose `X-Forwarded-Proto`/`X-Forwarded-Host` labd reads. Those headers must match `--public-url`, or labd answers 421. They are never identity. Refused together with `--tailscale` |
| `--tls-cert FILE --tls-key FILE` | labd serves TLS itself (1.2+, HTTP/2) and re-reads the files when they change |
| `--allow-plain-http` | Allows plain HTTP on a non-loopback `--listen`. Use it behind a proxy inside a private network. Without it, a non-loopback `--listen` without TLS is refused |
| `--terms-file FILE` | The terms a Mac's owner accepts before setup. Without it, labd uses its built-in terms |

`X-Forwarded-Prefix` is never read. A request outside the `--public-url` path gets 404, and so does `/maclabx` for `/maclab`.

## Kubernetes at chonkbase.net/maclab

The manifests are in `deploy/k8s/`:
- `base/` is the deployment at `/maclab`.
- `dedicated-host/` puts labd on its own origin instead.
- `terms/` supplies your own terms text.

They follow the cluster's existing conventions (the slopblender namespace on the same LKE cluster):
- ingress-nginx;
- cert-manager `letsencrypt-production` (DNS-01);
- `linode-block-storage-retain`;
- images in `ghcr.io/iconidentify` with the `ghcr-secret` pull secret.

### Origin and trust: read before choosing `/maclab`

`/maclab` separates paths, not origins. The UI keeps the Maintainer's token in the browser's `localStorage`, and that storage
belongs to the whole origin `https://chonkbase.net`. Any script served from **any** path of that origin can read the token,
call labd's API with it, or frame `/maclab`.

So `chonkbase.net/maclab` is right only when **every app on chonkbase.net is trusted as much as labd**. Today that includes:
- the chonkbase frontend at `/`;
- slopblender at `/slopblender`, until it is removed.

slopblender serves other people's uploads on that origin. Its README says they are extension-allow-listed (no HTML, SVG or JS)
and served with `nosniff` and a `sandbox` CSP. That is its own control, not labd's.

If the origin can't be trusted that far, use the supported alternative, labd on its own host: `kubectl kustomize deploy/k8s/dedicated-host`
gives `https://maclab.chonkbase.net` at `/`, with the same image and flags but no path.

### What the manifests set
- **One writer.** SQLite (WAL mode) on a ReadWriteOnce volume means `replicas: 1` and `strategy: Recreate`. A rollout stops the
  old pod before the new one starts, so two labds never open the same data. Never scale it above 1.
- **State:** one PVC at `/data` (60 Gi). It holds:
  - `labd.db` with its `-wal` and `-shm`;
  - the `artifacts/` store (capped by `--artifact-budget-gb`, 20 GiB by default);
  - `jobs/ builds/ frozen/ baselines/ screens/ serial/ audit/`;
  - `admin.token` and `builder.token`.
- **Pod:**
  - uid/gid 10001, `fsGroup` 10001 (the volume is the pod user's, not root's);
  - a read-only root filesystem, all capabilities dropped, the RuntimeDefault seccomp profile;
  - no service-account token;
  - no hostPath, and nothing from i9beef.
- **labd's args:** `--listen=0.0.0.0:7770 --allow-plain-http --data=/data --public-url=https://chonkbase.net/maclab --trusted-proxy=<CIDR> --maintainer=chris`.
  Plain HTTP stays inside the cluster, from the ingress controller only; TLS ends at the Ingress.
- **Ingress:**
  - path `/maclab`, `Prefix`, passed through **unchanged**: no rewrite-target, no snippet;
  - `proxy-read-timeout`/`proxy-send-timeout` 3700 s (`lab exec` is synchronous for up to 3630 s);
  - `proxy-buffering off` (the event stream, serial console and build log are streamed);
  - `proxy-request-buffering off`, `proxy-body-size 4g`.
- **NetworkPolicy:**
  - in: only from the `ingress-nginx` namespace;
  - out: DNS, and public port 443 (git for GitHub refs, ntfy, omarchy-m-testing.org);
  - nothing private.
- **No Secret in the manifests.** The tokens are made in `/data` on the first start, or come with migrated data. labd logs only the
  token file's *path* (`log in with lab login <url> "$(cat /data/admin.token)"`), never a token.

### Before the first apply: two values to set
1. **The image tag.** Build and push:
   `docker buildx build --platform linux/amd64 -t ghcr.io/iconidentify/maclab:<tag> --push .` (the Dockerfile is at the repo root).
   Then run `cd deploy/k8s/base && kustomize edit set image maclab=ghcr.io/iconidentify/maclab:<tag>`, or edit `newTag`.
   Copy `ghcr-secret` into the `maclab` namespace the way slopblender's deploy script does.
2. **The trusted proxy.** `--trusted-proxy` must name the addresses the ingress-nginx controller's pods connect *from*: the
   cluster's pod network.
   - Find it with `kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'` and `kubectl -n ingress-nginx get pods -o wide`.
   - The shipped value, `SET-INGRESS-NGINX-POD-CIDR`, is deliberately not a CIDR, so labd refuses to start until it is set.
   - The NetworkPolicy keeps every other pod in that range away from labd, so trusting the range trusts only the controller.

Render with `kubectl kustomize deploy/k8s/base` and check it. `deploy/k8s/test_manifests.py` runs the same checks offline.
Apply in this order:
1. namespace, PVC, Certificate;
2. wait for `certificate/maclab-tls` to be Ready;
3. Service, NetworkPolicy, Ingress, Deployment.

### Terms, and inviting a Mac
- A Mac's owner accepts labd's terms before anything is installed. Their version is the sha256 of the exact text.
  - To use your own text, put it in `deploy/k8s/terms/terms.txt` and deploy `deploy/k8s/terms`. That mounts it from a ConfigMap
    and adds `--terms-file`.
  - A changed text gets a new sha256. labd refuses an enrollment that accepted any other version.
- A Maintainer runs `lab enroll <name> --volunteer "<name>" --contact <c>`, or uses the web UI. labd answers with a **one-line join command**.
  - It holds a one-time activation token, `enr_…`, valid for 24 h, which travels only in an `Authorization` header, never in a URL.
  - The command downloads lab-agent over https, checks its sha256, and runs `lab-agent setup --server https://chonkbase.net/maclab --token-stdin`.
- `lab-agent setup` shows the terms and needs a typed `yes` on the terminal **before it changes anything**.
  - Without a terminal it stops, unless `--accept-terms <sha256>` names the exact current terms (unattended runs by a Maintainer).
- The token is used up by the first enrollment and bound to that Mac's activation key. If setup is interrupted, re-running it on the
  same Mac works until its first check-in; another Mac with the token gets 403.
- `lab enroll <name> --revoke` withdraws an unused invite.

### The container
The image (`Dockerfile` at the repo root) holds `labd`, plus `lab-agent-linux-arm64` next to it, which labd hands to invited Macs.

What labd itself runs or reads at run time:

| need | why | in the image |
|---|---|---|
| `git` | resolving a build's source ref (`git ls-remote`, `internal/server/sources.go`) | yes, plus outbound 443 to GitHub |
| IANA time zones | Availability windows (`internal/window`) | built into labd (`-tags timetzdata`), and `tzdata` |
| CA certificates | ntfy, publishing omarchy-m-test reports, GitHub | yes |
| `sh` | only for `--notify-cmd` | debian's `/bin/sh`; the pod sets no `--notify-cmd` |
| `tailscale` | only for `--tailscale` | not installed; the pod never uses it |
| Omarchy themes | the UI's palette, read from the controller user's home | not present; the UI uses its default palette |

There is no hostPath and no service account. labd never runs the Mac-side tools (systemctl, pacman, mkinitcpio and so on); those
belong to lab-agent on the Macs.

### What stays local
- **oobd** (on the M5: USB reset and serial console for the Macs) is called *by* labd at `http://<M5 LAN address>:7780`.
  - A pod in the cloud has no route to it, so those Macs run without hard reset or serial (tier 1).
  - Keep oobd private, and don't expose it or its token to make the cloud reach it. Only a private route (a VPN to the M5's
    network) brings it back.
- **lab-builder** polls labd outbound. It only needs `--server https://chonkbase.net/maclab`, plus `--ca-file` for a private CA.
- **The Macs** need outbound https to chonkbase.net, and **NTP** (see [The clock](#the-clock-comes-before-the-certificate)).
- Nothing else of i9beef is needed. The desktop `--notify-cmd` hook isn't set in the pod; use `--ntfy`.

## Moving labd from i9beef (and back)

Move only from a stopped, consistent state. Never run the old and new labd at the same time.

1. **Drain.** No running or queued jobs, and no leases: `lab status`.
2. **Point the agents first.**
   - Each Mac needs the new lab-agent binary (it understands https, `--ca-file` and the plain-http policy).
   - Run `sudo lab-agent setup --server https://chonkbase.net/maclab` on it: through `lab exec`, or on the Mac. This keeps the Mac's
     enrollment (its ID and secret); it only changes the URL and records the policy.
   - The agents then keep retrying until the new labd answers.
   - Check each Mac's `/etc/maclab/agent.json` afterwards: same `device_id`, new `server`, and an `allow_plain_http` key.
3. **Stop labd on i9beef.** Run `systemctl --user disable --now labd`, then check that no labd process is left and port 7770 is closed.
4. **Snapshot.**
   - Stopped, the database is closed. Run `sqlite3 ~/.local/share/maclab/labd.db 'PRAGMA wal_checkpoint(TRUNCATE)'` anyway.
   - Copy the **whole** data dir (`labd.db`, any `-wal`/`-shm`, every directory, both tokens) to a dated archive.
   - Keep that archive untouched: it is the rollback.
5. **Seed the PVC.**
   - Scale the Deployment to 0 and confirm no maclab pod exists.
   - Start a one-off pod as uid 10001 with the PVC mounted, and refuse to continue if `/data/labd.db` already exists.
   - Untar the archive into `/data`, then delete the one-off pod.
6. **Start** (scale to 1).
   - Artifact grants are memory-only and start empty. That is expected: bt2 asks for a new grant each run.
   - Check every Mac's check-in in `lab status`, then run `lab login https://chonkbase.net/maclab "<token>"` on each Maintainer machine.

**Rollback**:
1. Scale the Deployment to 0 and confirm the pod is gone.
2. Restore data on i9beef: either copy `/data` back (to keep what happened since), or use the untouched archive from step 4.
3. Re-point the agents to the old URL. That URL is plain HTTP to a non-loopback address, so it takes the explicit opt-in:
   `sudo lab-agent setup --server http://<i9beef tailnet address>:7770 --allow-plain-http`. Likewise run
   `lab login http://… "<token>" --allow-plain-http`.
4. Start labd on i9beef with `--allow-plain-http` on its tailnet `--listen`.

Nothing falls back to plain HTTP by itself: every client or agent set up for https refuses it until told explicitly.

## Clients: certificates and plain HTTP

Every client verifies TLS against the system roots, plus a private CA if you give one. None can turn verification off.

None follows a redirect: a 3xx answer is an error, so a token never goes anywhere it wasn't sent.

Plain `http://` is allowed only to a literal loopback address (127.0.0.0/8, ::1) or `localhost`, unless explicitly enabled.
There is no hostname or private-range guessing: `.local`, `.ts.net`, single-label names and RFC 1918 addresses all need the opt-in.

| client | private CA | plain http to a non-loopback host |
|---|---|---|
| `lab`, MCP | `lab login <url> <token> --ca-file F`, or `MACLAB_CA_FILE` | `lab login … --allow-plain-http` (saved), or `MACLAB_ALLOW_PLAIN_HTTP=1` |
| lab-agent | `setup … --ca-file F` (the PEM is kept in agent.json as `server_ca`) | `setup … --allow-plain-http`. An agent.json without the key, from an older lab-agent, keeps working over http with a warning |
| lab-builder | `--ca-file F` | `--allow-plain-http` |
| bt2, `scripts/` tools | `MACLAB_CA_FILE`, or `"ca_file"` in client.json | `MACLAB_ALLOW_PLAIN_HTTP=1`, or `"allow_plain_http": true` in client.json |
| bt2 on the Mac (`target/preflight.py fetch`) | agent.json `server_ca` | agent.json `allow_plain_http`, by the same rule as lab-agent |

The Python tools also ignore `http_proxy`/`https_proxy` and connect to labd directly.

Their policy is one block of code, `tools/bt2/bt2/labhttp.py`. Each of these carries a byte-for-byte copy, and a test fails if any
copy drifts:
- `scripts/boot-test/runtime.py`;
- `scripts/workflow/m1/controller.py`;
- `tools/bt2/target/preflight.py`.

A labd URL with a path (`https://chonkbase.net/maclab`) works everywhere: every API path is appended to it.

**Pinned sources.** Four Python files are pinned by sha256 elsewhere and are unchanged:
- `scripts/boot-test/frozen-controller-ea3.py` and its identical copy in `scripts/workflow/m1/`;
- `scripts/workflow/m1/retention-core/mirror_reuse.py`;
- `retain-controller.py`.

They are covered as follows:
- `scripts/boot-test/runtime.py`, the live `lab boot-test` runner, installs the policy as urllib's default opener before it loads
  the frozen SDK. The SDK's own calls then use it; `scripts/boot-test/test_https_runtime.py` drives them.
- Its earlier qualification was over plain HTTP and doesn't cover this transport.
- The M1 cohort helpers and the M5 retention scripts that load those files themselves keep their old behaviour: system roots
  (or `SSL_CERT_FILE`), redirects followed, plain http allowed.
  - Use them only against a loopback or tailnet labd.
  - Moving them needs a new, recorded revision of their pins.

**bt2 and artifact grants.** A Mac fetches from labd only what it is allowed to. Before the target's `fetch` step, bt2 makes one
explicit, journaled `grant-artifacts` step:
- `POST /api/devices/<name>/artifact-grants` for exactly that run's artifact shas, with a TTL of 2700 s (the fetch step's 1800 s, with margin);
- after `fetch` it revokes them (an empty list);
- a failed fetch leaves the grant to run out;
- a new run grants again in its own step; nothing extends a grant quietly.

## Other ways to serve HTTPS

**Caddy** (the simplest proxy): its defaults already pass the Host header through, have no read timeout, and flush streams and
unknown-length responses immediately.
```
chonkbase.net {
	@maclab path /maclab /maclab/*
	handle @maclab {
		reverse_proxy 127.0.0.1:7770
	}
}
```
labd then runs with `--listen 127.0.0.1:7770 --public-url https://chonkbase.net/maclab --trusted-proxy 127.0.0.1/32`.
Use `handle`, not `handle_path`: the path must reach labd unchanged.

**nginx.** Its defaults break labd, so all of this is needed:
```
location /maclab {
	proxy_pass http://127.0.0.1:7770;          # no URI part: the path passes through unchanged
	proxy_http_version 1.1;
	proxy_set_header Host $host;               # the default, $proxy_host, makes every browser change a 403
	proxy_set_header X-Forwarded-Host $host;
	proxy_set_header X-Forwarded-Proto $scheme;
	proxy_read_timeout 3700s;                  # lab exec: up to 3630 s with no bytes
	proxy_send_timeout 3700s;
	proxy_buffering off;                       # event stream, serial console, build log
	proxy_request_buffering off;
	client_max_body_size 4g;                   # the default 1m refuses every artifact
}
```
Don't put `X-Forwarded-Prefix` or a rewrite here.

**labd's own TLS**, with no proxy: `labd --listen 0.0.0.0:443 --tls-cert /etc/maclab/tls.crt --tls-key /etc/maclab/tls.key --public-url https://labd.example.org`.
labd re-reads the files when your ACME client renews them. No `--trusted-proxy` is needed.

## Operational limits

### The clock comes before the certificate
- After a reboot a Mac's clock can start in 1976 until NTP corrects it, about 25 s later. Until then every TLS certificate looks
  not yet valid, so the agent's check-ins fail.
- The agent logs that it is a clock problem, retries every 5 s, and gets through once the clock is right.
- A Lab boot has twice its boot timeout to reach labd (12 min by default). Those deadlines are absolute times, so a clock in the
  past doesn't fire them early.
- What this needs is NTP reachable from the Macs. A Mac whose clock never comes right can't reach an https labd at all.

### Long requests
- `lab exec` is synchronous, up to its `timeout_sec` (at most 3600 s, plus 30). Any proxy in front needs a read timeout above that.
- Job waits are asked in calls of at most 50 s.
