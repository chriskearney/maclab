package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedNetworks(t *testing.T) {
	trust, err := ParseTrust("10.1.1.0/24, 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{AdminToken: "adm_secret", Trust: trust}}
	h := s.admin(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	try := func(remote, token, fwd string) int {
		r := httptest.NewRequest("GET", labdAt+"/api/devices", nil)
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if fwd != "" {
			r.Header.Set("X-Forwarded-For", fwd)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	cases := []struct {
		name, remote, token, fwd string
		want                     int
	}{
		{"phone on the LAN", "10.1.1.42:51234", "", "", 200},
		{"loopback", "127.0.0.1:9", "", "", 200},
		{"phone as labd sees it (IPv4-mapped)", "[::ffff:10.1.1.42]:51234", "", "", 200},
		{"outside, IPv4-mapped", "[::ffff:192.168.7.3]:5000", "", "", 401},
		{"outside the LAN", "192.168.7.3:5000", "", "", 401},
		{"forged forwarded header", "192.168.7.3:5000", "", "10.1.1.42", 401},
		{"wrong token outside", "192.168.7.3:5000", "nope", "", 401},
		{"token from anywhere", "192.168.7.3:5000", "adm_secret", "", 200},
	}
	for _, c := range cases {
		if got := try(c.remote, c.token, c.fwd); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if _, err := ParseTrust("10.1.1.0/99"); err == nil {
		t.Error("bad CIDR accepted")
	}
	none := &Server{cfg: Config{AdminToken: "adm_secret"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.1.42:1"
	if none.trusted(r) {
		t.Error("trust must be off by default")
	}
}
