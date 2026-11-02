package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/iconidentify/maclab/internal/api"
)

// ntfyTopicFile holds the topic URL a Volunteer chose with `notify --topic`
// under the work directory. Check-ins carry it to labd.
const ntfyTopicFile = "ntfy-topic"

// jobNoticesFile holds "on" when the Volunteer asked for job notices with `notify --jobs on`.
const jobNoticesFile = "ntfy-jobs"

// loadJobNotices is whether the Volunteer asked for job notices; off when they have not.
func loadJobNotices(cfg *Config) (bool, error) {
	b, err := os.ReadFile(filepath.Join(cfg.workDir(), jobNoticesFile))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return strings.TrimSpace(string(b)) == "on", err
}

// loadNtfyTopic reads the Volunteer's own topic; "" when they have not chosen one.
func loadNtfyTopic(cfg *Config) (string, error) {
	b, err := os.ReadFile(filepath.Join(cfg.workDir(), ntfyTopicFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

// notifyCmd is `notify --topic URL`, which sends this Mac's notices to the
// Volunteer's own ntfy topic instead of the one labd made for it.
func notifyCmd(ctx context.Context, cfg *Config, sys System, args []string, out io.Writer) error {
	if cfg.Enrollment.Kind == api.KindLabOwned {
		return errors.New("a Lab-owned Mac has no Volunteer to notify")
	}
	if len(args) == 2 && args[0] == "--jobs" {
		return notifyJobs(cfg, args[1], out)
	}
	if len(args) != 2 || args[0] != "--topic" {
		return errors.New("usage: notify --topic URL | notify --jobs on|off")
	}
	topic := args[1]
	u, err := url.Parse(topic)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Trim(u.Path, "/") == "" {
		return fmt.Errorf("notify --topic %q: give the topic's full URL, like https://ntfy.sh/my-topic", topic)
	}
	if err := os.MkdirAll(cfg.workDir(), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(cfg.workDir(), ntfyTopicFile), []byte(topic+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(out, "Notices for this Mac now go to %s once it next checks in with labd.\n", topic)
	return nil
}

// notifyJobs is `notify --jobs on|off`: whether labd tells this Volunteer, on
// the Mac's topic, when a lab job starts on the Mac and when it is done.
func notifyJobs(cfg *Config, choice string, out io.Writer) error {
	if choice != "on" && choice != "off" {
		return fmt.Errorf("notify --jobs %q: say on or off", choice)
	}
	if err := os.MkdirAll(cfg.workDir(), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(cfg.workDir(), jobNoticesFile), []byte(choice+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(out, "Job notices are %s for this Mac once it next checks in with labd.\n", choice)
	return nil
}
