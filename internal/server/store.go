package server

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"

	"github.com/iconidentify/maclab/internal/api"
)

type store struct{ db *sql.DB }

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, secret_hash TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, name TEXT NOT NULL, label TEXT, model TEXT, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, device TEXT NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_device ON jobs(device, created);
CREATE TABLE IF NOT EXISTS builds (id TEXT PRIMARY KEY, key TEXT NOT NULL, created INTEGER NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS builds_key ON builds(key, created);
CREATE TABLE IF NOT EXISTS configs (device TEXT NOT NULL, kernel TEXT NOT NULL, sha TEXT NOT NULL, PRIMARY KEY(device, kernel));`)
	if err != nil {
		return nil, err
	}
	return &store{db}, nil
}

func (s *store) saveDevice(d *api.Device, secretHash string) error {
	b, _ := json.Marshal(d)
	_, err := s.db.Exec(`INSERT INTO devices(id,name,secret_hash,data) VALUES(?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, data=excluded.data`, d.ID, d.Name, secretHash, string(b))
	return err
}

type deviceRow struct {
	d          api.Device
	secretHash string
}

func (s *store) devices() ([]deviceRow, error) {
	rows, err := s.db.Query(`SELECT secret_hash, data FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deviceRow
	for rows.Next() {
		var r deviceRow
		var data string
		if err := rows.Scan(&r.secretHash, &data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &r.d); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *store) addToken(hash string, req api.EnrollTokenRequest, exp time.Time) error {
	_, err := s.db.Exec(`INSERT INTO tokens(token_hash,name,label,model,expires) VALUES(?,?,?,?,?)`, hash, req.Name, req.Label, req.Model, exp.Unix())
	return err
}

// takeToken consumes a one-time enrollment token.
func (s *store) takeToken(hash string) (*api.EnrollTokenRequest, error) {
	var r api.EnrollTokenRequest
	var exp int64
	err := s.db.QueryRow(`DELETE FROM tokens WHERE token_hash=? RETURNING name,label,model,expires`, hash).Scan(&r.Name, &r.Label, &r.Model, &exp)
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > exp {
		return nil, sql.ErrNoRows
	}
	return &r, nil
}

func (s *store) saveJob(j *api.Job) error {
	b, _ := json.Marshal(j)
	_, err := s.db.Exec(`INSERT INTO jobs(id,device,created,state,data) VALUES(?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET state=excluded.state, data=excluded.data`, j.ID, j.Spec.Device, j.Created.UnixNano(), string(j.State), string(b))
	return err
}

func (s *store) job(id string) (*api.Job, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM jobs WHERE id=?`, id).Scan(&data); err != nil {
		return nil, err
	}
	var j api.Job
	return &j, json.Unmarshal([]byte(data), &j)
}

func (s *store) jobs(device string, limit int, unfinished bool) ([]*api.Job, error) {
	q := `SELECT data FROM jobs WHERE (?='' OR device=?)`
	if unfinished {
		q += ` AND state != 'done'`
	}
	q += ` ORDER BY created DESC LIMIT ?`
	return scanJobs(s.db.Query(q, device, device, limit))
}

// kernelJobs lists the finished jobs that ran a kernel artifact, newest first.
func (s *store) kernelJobs(sha string) ([]*api.Job, error) {
	return scanJobs(s.db.Query(`SELECT data FROM jobs WHERE json_extract(data, '$.spec.kernel')=? AND state='done' ORDER BY created DESC`, sha))
}

func scanJobs(rows *sql.Rows, err error) ([]*api.Job, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*api.Job
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var j api.Job
		if err := json.Unmarshal([]byte(data), &j); err != nil {
			return nil, err
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

func (s *store) saveBuild(b *api.Build) error {
	d, _ := json.Marshal(b)
	_, err := s.db.Exec(`INSERT INTO builds(id,key,created,state,data) VALUES(?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET state=excluded.state, data=excluded.data`, b.ID, b.Key, b.Created.UnixNano(), string(b.State), string(d))
	return err
}

func (s *store) builds(where string, args ...any) ([]*api.Build, error) {
	rows, err := s.db.Query(`SELECT data FROM builds WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*api.Build
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var b api.Build
		if err := json.Unmarshal([]byte(data), &b); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

func (s *store) configFor(device, kernel string) string {
	var sha string
	s.db.QueryRow(`SELECT sha FROM configs WHERE device=? AND kernel=?`, device, kernel).Scan(&sha)
	return sha
}

func (s *store) setConfig(device, kernel, sha string) error {
	_, err := s.db.Exec(`INSERT INTO configs(device,kernel,sha) VALUES(?,?,?) ON CONFLICT(device,kernel) DO UPDATE SET sha=excluded.sha`, device, kernel, sha)
	return err
}
