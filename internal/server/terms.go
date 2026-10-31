package server

import (
	"crypto/sha256"
	"encoding/hex"
)

// DefaultTerms are what a Mac's owner reads and accepts before the Mac joins
// the lab, unless labd was given its own (--terms-file). They describe what
// the lab does to a Mac, plainly; lab-agent setup shows them, the owner
// types yes, and the Mac's record keeps the sha256 of the text accepted.
const DefaultTerms = `MACLAB PARTICIPATION TERMS

Joining this lab hands its Maintainers real control over this Mac. Read what
that means before you accept.

1. Privileged code. The lab boots test Linux kernels on this Mac and may
   install test packages (Releases). A kernel or package runs with full
   control of the machine, your files included. A test kernel can crash,
   hang, lose data or misbehave.

2. Reboots. The lab reboots this Mac into test kernels and back to its own
   kernel without asking each time: within its Availability window on a
   Volunteer's Mac, at any time on a Lab-owned one.

3. What the lab collects. Hardware facts, journals and kernel logs, test
   output and, while a job or lease holds the Mac, screenshots and its live
   journal. The lab's Maintainers read them in labd.

4. Commands. At Access level Full, Maintainers may run commands and scripts
   as root on this Mac. The default, Qualification, refuses those, but not
   test kernels or Release installs.

5. Your controls on a Volunteer's Mac. You set the Availability window,
   pause the lab, choose the Access level, read the Audit log of every
   Maintainer action on this Mac, and leave at any time with
   "sudo lab-agent leave".

6. Trust. Join only a lab whose Maintainers you trust with this machine and
   what is on it.

This describes how the lab works and is recorded with your acceptance. It is
not a legal agreement.
`

// terms is the text a Mac's owner accepts, and its sha256.
func (s *Server) terms() (text, sum string) {
	text = s.cfg.Terms
	if text == "" {
		text = DefaultTerms
	}
	h := sha256.Sum256([]byte(text))
	return text, hex.EncodeToString(h[:])
}
