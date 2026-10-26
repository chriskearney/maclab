package workflow

// Only completed bind outputs may be externalized. Their full canonical bytes
// remain under the workflow's private directory; helpers/verdicts stay inline.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Archive only bind values consumed by declared later phases. Terminal leaf
// assertions remain inline for existing frontend restoration verification.
func (r *Runner) archivedBindKinds() map[string]bool {
	consumed := map[string]bool{}
	for _, p := range r.Plan.Phases {
		if p.InputPhase != "" {
			consumed[p.InputPhase] = true
		}
		for _, v := range p.Bind {
			consumed[v.From] = true
		}
		if p.M1Admission != nil {
			consumed[p.M1Admission.BootID.From] = true
			consumed[p.M1Admission.AgentSHA256.From] = true
		}
	}
	eligible := map[string]bool{}
	for _, p := range r.Plan.Phases {
		eligible[p.ID] = p.Kind == "bind" && consumed[p.ID]
	}
	return eligible
}

func (r *Runner) bindArchiveDir(create bool) (string, error) {
	base, err := filepath.Abs(r.Dir)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "bind-outputs")
	if create {
		if err = os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	u, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 || u.Uid != uint32(os.Geteuid()) {
		return "", errors.New("bind output archive must be an owned private real directory")
	}
	return dir, nil
}
func (r *Runner) readBindOutput(pin Pin, outputSHA string) ([]byte, error) {
	dir, err := r.bindArchiveDir(false)
	if err != nil {
		return nil, err
	}
	if !shaRE.MatchString(pin.SHA256) || pin.SHA256 != outputSHA || pin.Bytes <= 0 || pin.Bytes > MaxJSON || pin.Path != filepath.Join(dir, pin.SHA256+".json") {
		return nil, errors.New("bind output pin identity/path/bound mismatch")
	}
	f, st, err := openRegular(pin.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	u, ok := st.Sys().(*syscall.Stat_t)
	if !ok || u.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0600 || u.Nlink != 1 || st.Size() != pin.Bytes {
		return nil, errors.New("bind output is not an owned private regular file")
	}
	b, err := readRegular(pin.Path, MaxJSON)
	if err != nil {
		return nil, err
	}
	end, err := f.Stat()
	if err != nil || !same(st, end) {
		return nil, errors.New("held bind output drift")
	}
	if err = finalSame(pin.Path, st); err != nil {
		return nil, err
	}
	normalized, err := canonical(b)
	if err != nil || !bytes.Equal(b, normalized) || int64(len(b)) != pin.Bytes || Hash(b) != pin.SHA256 {
		return nil, errors.New("retained canonical bind output drift")
	}
	return b, nil
}
func (r *Runner) retainBindOutput(b []byte, outputSHA string) (*Pin, error) {
	if len(b) == 0 || len(b) > MaxJSON || Hash(b) != outputSHA {
		return nil, errors.New("canonical bind output exceeds bound or hash differs")
	}
	dir, err := r.bindArchiveDir(true)
	if err != nil {
		return nil, err
	}
	pin := &Pin{Path: filepath.Join(dir, outputSHA+".json"), SHA256: outputSHA, Bytes: int64(len(b))}
	if _, err = os.Lstat(pin.Path); err == nil {
		actual, e := r.readBindOutput(*pin, outputSHA)
		if e != nil || !bytes.Equal(actual, b) {
			return nil, fmt.Errorf("existing bind archive refused: %w", e)
		}
		return pin, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Never rename over an existing destination. Link provides exclusive publish;
	// both the file and directory are synchronized before the state refers to it.
	f, err := os.CreateTemp(dir, ".bind-*")
	if err != nil {
		return nil, err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	actual, err := readRegular(temp, MaxJSON)
	if err != nil || !bytes.Equal(actual, b) {
		return nil, errors.New("bind output temporary readback differs")
	}
	if err = os.Link(temp, pin.Path); err != nil {
		return nil, err
	}
	if err = os.Remove(temp); err != nil {
		return nil, err
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	if err = syncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	actual, err = r.readBindOutput(*pin, outputSHA)
	if err != nil || !bytes.Equal(actual, b) {
		return nil, errors.New("published bind output readback differs")
	}
	return pin, nil
}
func (r *Runner) hydrateBindOutputs(s *State) error {
	eligible := r.archivedBindKinds()
	for id, rec := range s.Records {
		if rec.OutputPin == nil {
			continue
		}
		if rec.State != "done" || !eligible[id] || len(rec.Output) != 0 {
			return fmt.Errorf("output pin allowed only on cold completed bind record: %s", id)
		}
		b, err := r.readBindOutput(*rec.OutputPin, rec.OutputSHA256)
		if err != nil {
			return fmt.Errorf("bind output archive %s: %w", id, err)
		}
		rec.Output = json.RawMessage(b)
	}
	return nil
}
func (r *Runner) coldBindState(s *State) (*State, error) {
	cold := *s
	cold.Records = make(map[string]*Record, len(s.Records))
	eligible := r.archivedBindKinds()
	for id, rec := range s.Records {
		copyRec := *rec
		if rec.OutputPin != nil && (rec.State != "done" || !eligible[id]) {
			return nil, fmt.Errorf("output pin on non-completed-bind: %s", id)
		}
		if rec.State == "done" && eligible[id] {
			b, err := canonical(rec.Output)
			if err != nil || Hash(b) != rec.OutputSHA256 || len(b) > MaxJSON {
				return nil, fmt.Errorf("cannot archive invalid bind output: %s", id)
			}
			if rec.OutputPin != nil {
				actual, e := r.readBindOutput(*rec.OutputPin, rec.OutputSHA256)
				if e != nil || !bytes.Equal(actual, b) {
					return nil, fmt.Errorf("retained bind output changed: %s", id)
				}
				copyRec.OutputPin = rec.OutputPin
			} else {
				copyRec.OutputPin, err = r.retainBindOutput(b, rec.OutputSHA256)
				if err != nil {
					return nil, err
				}
			}
			copyRec.Output = nil
		}
		cold.Records[id] = &copyRec
	}
	return &cold, nil
}
