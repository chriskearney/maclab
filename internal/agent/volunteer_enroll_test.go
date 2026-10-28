package agent

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetupRefusesAutologinOnAVolunteerMac(t *testing.T) {
	err := refuseOnVolunteer(true, false)
	if err == nil || !strings.Contains(err.Error(), "--autologin") {
		t.Fatalf("autologin on a Volunteer Mac: %v", err)
	}
}

func TestSetupRefusesStayAwakeOnAVolunteerMac(t *testing.T) {
	err := refuseOnVolunteer(false, true)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "stay-awake") {
		t.Fatalf("stay-awake on a Volunteer Mac: %v", err)
	}
}

func TestSetupAcceptsAVolunteerMacWithNeitherFlag(t *testing.T) {
	if err := refuseOnVolunteer(false, false); err != nil {
		t.Fatalf("plain Volunteer setup refused: %v", err)
	}
}

func TestSetupPrintsTheTopicWithAQRCode(t *testing.T) {
	var out bytes.Buffer
	if err := printTopicQR(&out, "maclab-k3j9x2m4"); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "maclab-k3j9x2m4") {
		t.Fatalf("the topic is not printed:\n%s", s)
	}
	if strings.Count(s, "\n") < 10 || !strings.ContainsAny(s, "█▀▄") {
		t.Fatalf("no QR code drawn:\n%s", s)
	}
}

func TestTheQRCodeDependsOnTheTopic(t *testing.T) {
	var a, b bytes.Buffer
	printTopicQR(&a, "maclab-aaaaaaaa")
	printTopicQR(&b, "maclab-bbbbbbbb")
	if a.Len() == 0 || a.String() == b.String() {
		t.Fatal("two topics drew the same (or no) QR code")
	}
}
