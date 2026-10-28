# Where today's flow assumes a LAN Mac beside labd

Research for malik-na/maclab#3 (part of #1). Vocabulary follows `CONTEXT.md`:
Volunteer, Maintainer, Release, Qualification, Availability window, Known-good kernel.

**Question.** What breaks or behaves badly in today's enrollment, agent and
notification flow when the Mac is a remote Volunteer Mac instead of a LAN Mac
beside labd?

**Fixed by the map.** labd is reachable only over Tailscale. A Volunteer Mac is
remote, is the Volunteer's daily machine, has **no OOB controller**, may be used
only inside its Availability windows, and its Volunteer is the human for
`needs_hands`. Several named Maintainers, each with their own credentials, take
the place of the single admin token.

**Sources.** This codebase at `81abf6a` (branch `main`) and `README.md`. Every
claim cites `file:line`. Nothing here was run on hardware or over a tailnet.

**Severity.**
- **blocks enrollment**: a Volunteer Mac can't safely or practically join.
- **blocks Qualification**: it joins, but it can't reliably produce a
  Qualification verdict for a Release.
- **degrades**: it works, but worse, less safely, or with less evidence.

Each item ends with one line of direction (→). The decisions come later.

---

## Top findings

1. **Nothing knows about Availability windows.** Jobs start, and Macs reboot,
   whenever the Mac checks in and is `ready`. That includes the `--omt-every`
   scheduler, which reboots idle Macs by itself. A Volunteer who opens their
   laptop can find it rebooting into a test kernel. (A1, A2)
2. **Without OOB, any test kernel that hangs without panicking, or boots but
   can't reach labd, strands the Volunteer's daily machine.** It waits in
   `needs_hands` until they hold the power button. That includes losing Wi-Fi or
   Tailscale. No evidence from the failed boot is collected, even after the Mac
   comes back. (O1, O2, O3)
3. **`needs_hands` goes to one global ntfy topic or command, not to the
   Volunteer.** The Volunteer has no credential to see their Mac's state or
   instructions. (H1, H2, S4)
4. **There is one admin token, and it is also root on every Mac.** `--trust` on
   a tailnet CIDR would give every tailnet node, Volunteer Macs included, root
   on every other Volunteer Mac. `accepted_by`, `approved_by` and the lease
   holder are self-declared strings. (S1, S2, S3)
5. **`--autologin` plus stay-awake permanently removes the lock screen from the
   Volunteer's daily machine.** Without autologin, omarchy-m-test can't run, so
   installed jobs, and with them Qualification, can't run. (H4)

---

## 1. Assumes the Mac is always available

| # | Where | What happens on a remote Volunteer Mac | Severity |
|---|---|---|---|
| A1 | `internal/server/runner.go:98-110`, `internal/server/server.go:829-931` (`Submit`) | A queued job waits with no deadline (`waitFor(ctx, 0, ...)`) until the Mac is alive and `ready`/`new`, then takes it. `Submit` accepts a job at any time, and nothing in `api.Device` (`internal/api/types.go:49-67`) records a window. So a Volunteer who opens their laptop outside an Availability window has it rebooted into a test kernel within seconds. A job queued for an absent Mac sits `queued` indefinitely. → Gate job start (and `Submit`) on the device's Availability window; give queued jobs a deadline. | **blocks enrollment** (no Volunteer can lend a daily machine on these terms) |
| A2 | `internal/server/omt.go:340-370` | With `--omt-every`, labd submits a known-good job on every `ready` Mac with a GUI user every interval. That job reboots the Mac (`cmd/labd/main.go:32` says "reboots the Mac"). An idle-but-in-use Volunteer Mac shows as `ready`. → Run scheduled refreshes only inside the window, or not on Volunteer Macs. | **blocks enrollment** when `--omt-every` is on |
| A3 | `internal/server/runner.go:129-137` | If a Mac is still on a lab entry, the next job reboots it to known-good before staging. This is another reboot the Volunteer didn't see coming. Inside a window it's fine. | degrades |
| A4 | `internal/server/server.go:161-169`, `internal/server/device.go:17` | A Mac that is off or away shows as `offline` ("no heartbeat since ..."). That looks the same as a broken Mac. Nothing tells "outside its window" apart from "lost". → Show and report outside-window as its own state. | degrades |
| A5 | `internal/server/device.go:349-352, 409-427` | During a test, a Mac that sleeps keeps its command alive for up to `maxSleep` (1 h). After 2 min it notifies "Press a key on X to wake it". The quiet grace without a sleep notice is only 60 s, and then the job is lost. A Volunteer closing the lid at the end of a window turns a running test into `asleep` and then `lost`, and the verdict becomes `panicked` (`runner.go:492-510`). | degrades (a spurious failure in a Qualification run) |
| A6 | `internal/server/installed.go:880-893`, `:1055` | Promotion needs the Mac checking in *now*, idle, and on the installed kernel. The agent then has one minute (`recordKnownGoodTimeout`, `:46`) to record the Known-good kernel. A Maintainer can't promote a Volunteer Mac outside its window, and a Tailscale blip during that minute fails the promotion (which rolls back cleanly). → Queue the promotion to run at the Mac's next check-in. | degrades |
| A7 | `internal/server/installed.go:122-195`, `internal/installed/installed.go:110,157` | A Release's frozen manifest lists its Macs (`Macs map`), and `PINS.preinstall` pins every Mac's pre-install files once. A Volunteer Mac that enrolls, or reaches a window, after the freeze can't take part in that Release's installed runs. | blocks Qualification (for late or intermittently available Macs) |

## 2. Assumes the Mac is on a LAN beside labd

| # | Where | What happens on a remote Volunteer Mac | Severity |
|---|---|---|---|
| L1 | `internal/server/runner.go:234` (stage call, 20 min), `internal/agent/agent.go:472-500` (`fetch`), `internal/agent/stage.go:316-330` | The 20-minute stage budget covers downloading the artifact, extracting it, and building the initramfs or UKI (the last step alone may take up to 10 min, `stage.go:399`, `limine.go:311`). `fetch` has no resume and no retry: one dropped connection fails the job as `stage_failed`. A full kernel package over a home uplink or a DERP relay can come close to the budget. → Resumable, retried downloads; a stage timeout that grows with artifact size; pre-fetch before the window opens. | blocks Qualification (spurious `stage_failed` on slow links) |
| L2 | `internal/server/server.go:80-88`, `internal/server/device.go:17`, `internal/agent/agent.go:85,205` | The heartbeat interval is 8 s, a device counts as alive for 20 s (`aliveWindow`), it goes offline after 1 min, and the client timeout is 30 s. All of these are tuned for a LAN. Tailscale path changes (direct to DERP) or Wi-Fi roaming can drop a Mac out of `aliveWindow`. That changes which way `hExec` goes (`exec.go:34-49`), refuses screenshots (`live.go:204-208`), and makes the ladder skip the soft reboot (`recover.go:70`). | degrades |
| L3 | `internal/server/runner.go:254`, `internal/server/server.go:83-85` (`BootTimeout` 4 min) | After every reboot the Mac must bring up Wi-Fi, then `tailscaled`, then `lab-agent`, all within 4 min. The unit waits only for `network-online.target` (`internal/agent/setup.go:24-36`), not for Tailscale. The agent retries every 5 s (`agent.go:143-146`), so this usually works. A slow join or an expired Tailscale node key turns into `hung` or `needs_hands`. → Order the unit after `tailscaled`; disable key expiry for lab nodes. | degrades |
| L4 | `internal/agent/stage.go:316-330`, test kernels in general | On a LAN Mac a test kernel needs working networking to check in. A Volunteer Mac also needs `tun` and a working `tailscaled`. A kernel that breaks Wi-Fi or `tun` boots fine, never checks in, and never reboots (see O2). | blocks Qualification (for that Mac, until its Volunteer power-cycles it) |
| L5 | `cmd/lab/main.go:147-149`, `README.md:110-117` | `lab enroll` prints a `lab-agent setup --server <c.URL>` command that uses the *Maintainer's* labd URL (it might be `localhost` or a LAN IP), and it says "copy lab-agent over", which assumes the Maintainer can scp to the Mac. A Volunteer needs the tailnet name, and a way to get the binary. | degrades enrollment |
| L6 | `deploy/labd.service:8,11-13`, `README.md:326-335` (`## Phones and the LAN`) | The docs and the sample unit present `--trust 192.168.1.0/24` as the normal way for phones and browsers to get in. On a tailnet, the equivalent is `100.64.0.0/10`, which covers every node, Volunteer Macs included (see S2). | degrades (an unsafe default to copy) |
| L7 | `internal/server/live.go:283-290` (`capture`), `internal/agent/agent.go:438,550` | A screen upload has 1 min, a file upload has 10 min and 8 retries. Logs and screenshots are small, so this is probably fine over Tailscale. `uploadDir` drops a file it can't upload and only logs it (`agent.go:511-514`). For installed jobs, a missing kernel log fails the run (`runner.go:347-352,394-395`). | degrades |

## 3. Assumes OOB is present

`Device.Tier()` (`internal/api/types.go:72-81`) gives a Volunteer Mac tier 0, or
tier 1 if `apple_wdt` is armed. Never tier 2.

| # | Where | What happens on a remote Volunteer Mac | Severity |
|---|---|---|---|
| O1 | `internal/server/recover.go:67-129` | The ladder is a soft reboot (only if the agent still answers), then hard reset ×2 (`if ctl != nil`, skipped), then `needs_hands`. A Mac that is hung or off the network goes straight from detection to `needs_hands`. The humanAction says so (`recover.go:167-168`). | blocks Qualification (each such Mac stalls until its Volunteer acts) |
| O2 | `internal/agent/setup.go:92-108`, `README.md:101-103` | Without OOB, only `panic=10` (for a panic) and the systemd watchdog (for a hung userspace, `RuntimeWatchdogSec=30s`) recover the Mac by itself. A kernel that boots and keeps systemd healthy but has no network, or that hangs before the watchdog is armed (`README.md:307-308`), never reboots by itself. The Volunteer's daily machine sits on the test kernel. → An agent- or initramfs-side dead-man reboot to known-good if labd is unreachable for N minutes after a lab boot. | blocks Qualification |
| O3 | `internal/server/runner.go:254-262`, `:468-490`; `internal/server/recover.go:22-40` | Serial is the evidence for an early crash. Panic and stall detection from serial (`recover.go:29-40`) and `serial.log` (`server.go:271-289`) are both missing. A boot that never checks in is classified with no kernel line (`boot_failed`/`hung`, "see serial.log and prevboot/journal.txt"). The `prevboot` journal is collected only on the fell-back path (`runner.go:268`) and after a crash during a test (`runner.go:505-508`). When the ladder ends in `needs_hands`, the job finishes and nothing collects the previous boot after the Volunteer power-cycles the Mac (`runner.go:155-165`, `device.go:148-161`). → On the next check-in after `needs_hands`, collect `journalctl -b -1` into that job. | degrades (much weaker evidence for "not qualified") |
| O4 | `cmd/lab/shell.go:13-16`, `internal/server/live.go:297-312`, `internal/server/exec.go:39-48`, `internal/server/server.go:795-806` | `lab shell`/`console`, `lab serial`, `lab oob` and the serial fallback of `lab exec` all return 409/404 ("has no out-of-band controller"). `lab exec` works only while the agent is alive. Nothing in the lab can reach a Mac whose network is down. | degrades |
| O5 | `internal/agent/setup.go:110-114`, `:391-416` | `setup` always enables an autologin getty on `ttySAC0` as the GUI user. The comment reasons that "anyone with the controller or the cable is already physically at the machine". On a Volunteer Mac nobody in the lab uses it, but it leaves a logged-in shell for anyone who plugs in a USB-C debug cable. → Skip the serial getty when no OOB is planned. | degrades (Volunteer security) |
| O6 | `internal/server/live.go:120-136`, `internal/server/device.go:135-137`, `internal/server/runner.go:229-232` | `rearmSerial` and `Serial: d.OOB != nil` are already no-ops without OOB. Nothing breaks. Listed so it isn't re-checked. | none |

## 4. Assumes the human is in the room (and is a Maintainer)

| # | Where | What happens on a remote Volunteer Mac | Severity |
|---|---|---|---|
| H1 | `internal/server/notify.go:19-50`, `cmd/labd/main.go:24-25`, `internal/server/server.go:39-40` | There is one `--ntfy` topic URL and one `--notify-cmd` for the whole lab. Every `needs_hands` alert (`recover.go:127`), every "is back" (`device.go:158`), every "asleep during a test" (`device.go:434`) and every failed-job notice (`runner.go:192-194`) goes to the same place. The Volunteer who has to press the button isn't on it, unless every Volunteer shares one topic and gets every other Mac's alerts. `--notify-cmd` does get `MACLAB_DEVICE` (`notify.go:44`), so routing per device is only possible through a hand-written script. → Per-Mac (per-Volunteer) notification target; Maintainers get a copy. | blocks Qualification (`needs_hands` on a Volunteer Mac never reaches the Volunteer) |
| H2 | `internal/server/recover.go:143-173`, `README.md:88-97` | The instruction is written for someone at a lab desk ("Find m1air (MacBook Air M1, left desk)", with the label described as "where the Mac physically is", `cmd/lab/main.go:137`). For a Volunteer, it's their own laptop. It doesn't say that the Mac is running a lab kernel, that their data is fine, or what to do if they need the machine now. The wording is the only problem. | degrades |
| H3 | `cmd/lab/mcp.go:21`, `README.md:297-298` | AI agents are told that `needs_hands` means "tell the user". The user is a Maintainer, not the Volunteer. | degrades |
| H4 | `internal/agent/setup.go:115-123`, `:418-442`; `internal/agent/linux.go:298-328`; `internal/server/installed.go:226-228` | GUI tests, and so omarchy-m-test, need the GUI user's Hyprland session to exist after a lab reboot ("is autologin enabled?"). `--autologin` gets there by turning on SDDM autologin and Omarchy's stay-awake (no idle lock, no screensaver), permanently. An installed job *requires* omarchy-m-test. So a Volunteer either gives up the lock screen on their daily machine at all times, or their Mac can't take part in Qualification. → Autologin and stay-awake only for lab boots (or only during a window), restored afterwards. | blocks Qualification without autologin; blocks enrollment for any Volunteer who won't accept it |
| H5 | `internal/agent/setup.go:46-168` | `setup` is a one-shot root run with no `uninstall` or "pause". It edits the bootloader config, sysctl, the watchdog, SDDM and the user's Omarchy state. A Volunteer who wants their Mac back has no supported way to undo it (there are backups, but no command). There is also no `DELETE /api/devices/{name}` (`internal/server/server.go:331-386`). | degrades enrollment |
| H6 | `internal/agent/setup.go:125-147`, `internal/server/server.go:472-527`, `internal/server/store.go:73-85` | The enroll token is single-use and expires in 24 h. `setup` consumes it (`Enroll`) *before* it saves `/etc/maclab/agent.json` and starts the service. If a later step fails, labd keeps a device with that name and the Mac has no secret. A new token for the same name is refused ("already enrolled", `server.go:482-484`), and there is no API to delete the device. With the Mac across the room this costs a minute. With a remote Volunteer it takes a Maintainer with shell on labd's database. | blocks enrollment (on any failed first attempt) |
| H7 | `internal/server/omt.go:264-318`, `cmd/labd/main.go:30-31`, `internal/server/runner.go:328-334` | `--publish` and `--omt-publish` upload a signed hardware report of the Volunteer's Mac to omarchy-m-testing.org. The deletion link is stored only in labd's job directory (`omt.go:317`, mode 0600). Nothing records the Volunteer's consent, and the Volunteer can't delete the report themselves. | degrades (consent) |

## 5. Assumes a single admin

| # | Where | What happens with several Maintainers and Volunteers | Severity |
|---|---|---|---|
| S1 | `cmd/labd/main.go:42-52`, `internal/server/server.go:401-409`, `cmd/lab/main.go:770-786`, `internal/client/client.go:33-46` | There is one `admin.token`, created on first start. Every Maintainer must share it. Every `/api/...` route except `/api/agent/*`, `/api/builder/*` and `/api/auth` is behind that one token (`server.go:339-383`). There is no per-person identity, no revocation short of rotating everyone's token, and no audit of who did what. | blocks Qualification (a verdict needs named Maintainers, `CONTEXT.md`) |
| S2 | `internal/server/server.go:41-43`, `:411-425`, `cmd/labd/main.go:28` | `--trust` gives admin to every source IP in a CIDR. Over Tailscale the only practical range is the tailnet. That includes every Volunteer Mac and every other device a Volunteer has on the tailnet. Admin includes `POST /api/devices/{n}/exec`, which runs as root (`exec.go:18-21`). One compromised Volunteer laptop could then run root on every other Volunteer's Mac. → Don't trust by network on a shared tailnet; tie access to named credentials (or Tailscale identity). | blocks enrollment if `--trust` is set to the tailnet; otherwise degrades |
| S3 | `internal/server/installed.go:684,727` (`approved_by`), `:796,804,979` (`accepted_by`); `cmd/lab/main.go:87-98` (`holder()`), `internal/server/server.go:708-748` (lease) | Who approved a manifest, who accepted a promotion, and who holds a lease are free-text strings. `holder()` defaults to `user@hostname`, and anyone can set `MACLAB_HOLDER`. The promotions ledger records whatever name it is given. A lease fences only callers that give a different holder string. → Fill these from the authenticated Maintainer. | blocks Qualification (the verdict isn't attributable) |
| S4 | `internal/server/server.go:340-383` | There is no role between "admin" and "agent". A Volunteer can't see their own Mac's state or `needs_hands` instruction, can't mark it unavailable, and can't cancel a job on it, without the lab-wide root token. | degrades (and adds to H1) |
| S5 | `internal/server/server.go:349-353`, `internal/server/live.go:194-221`, `internal/agent/linux.go:334-350`; `internal/server/exec.go:18-55` | Any admin can take a screenshot of the Volunteer's desktop (`kmsgrab` reads the whole scanout) and read its journal (`/logs`) at any time, inside a window or not. `lab exec` runs any root command on the Volunteer's daily machine. This is acceptable for a lab-owned Mac. For a Volunteer's Mac it needs at least consent, per-Maintainer attribution and window limits. | blocks enrollment (Volunteer trust) |
| S6 | `internal/server/installed.go:7`, `:163-166` | `PINS.preinstall` "is written by hand", meaning on labd's filesystem. No API sets it, so whoever prepares a Release's pre-install pins needs shell on the labd host. labd also never installs the Release on the Mac. Someone with root on the Mac does that before `freeze-entry` (`installed.go:736-795`). On a Volunteer Mac, that is either the Volunteer or a Maintainer using `lab exec`. | degrades (one Maintainer is privileged) |

## Minor bug found on the way

- `internal/server/device.go:434-435` sends the "asleep during a test" notice
  with `Priority: "high"`, but `notify.go:32-33` maps only `urgent` and `low`.
  ntfy gets an empty `Priority` and `Tags` header, so the notice arrives at
  default priority.

## Not checked

- Whether Omarchy on Apple Silicon encrypts the root filesystem by default. The
  code never mentions a boot-time disk passphrase (searched for
  `luks|cryptsetup|passphrase`: only a GRUB comment, `internal/agent/grub.go:14`).
  If a Volunteer's Mac asks for one at boot, every lab reboot waits for a human,
  and that alone would block Qualification. Verify this on a real Omarchy Asahi
  install.
- Real artifact sizes and Tailscale/DERP throughput. L1's risk is an inference
  from the code's timeouts, not a measurement.
