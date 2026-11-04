package loop

import (
	"strings"
	"testing"
)

func TestParseVerdictRejectsAnUnknownFault(t *testing.T) {
	for _, fault := range []string{"Hang_Late", "hang", " hang_late", "kernel_panic"} {
		out := `{"fault":"` + fault + `"}`
		v, err := parseVerdict([]byte(out))
		if err == nil {
			t.Errorf("%q parsed as %+v", out, v)
		} else if !strings.Contains(err.Error(), `"`+fault+`"`) {
			t.Errorf("%q: error %q does not name the fault", out, err)
		}
	}
	// In prose too: the last verdict found is the one checked.
	if _, err := parseVerdict([]byte("Verdict:\n{\"fault\":\"Hang_Late\"}\nDone.")); err == nil {
		t.Error("an unknown fault in prose parsed")
	}
}

func TestParseVerdictAcceptsUnsure(t *testing.T) {
	v, err := parseVerdict([]byte(`{"fault":"unsure","human_needed":true}`))
	if err != nil || v.Fault != Unsure || !v.HumanNeeded {
		t.Fatalf("%+v, %v", v, err)
	}
}

func TestParseVerdictFindsTheVerdict(t *testing.T) {
	for _, c := range []struct {
		name, out string
		want      Mode
	}{
		{"prose with braces after", "Here it is:\n{\"fault\":\"panic_late\",\"evidence\":[\"a\"]}\nNote: the log had {weird} braces and a } stray one.", PanicLate},
		{"fenced json block", "I read boot0.\n```json\n{\n  \"fault\": \"netdown\",\n  \"lab_outcome_agrees\": true\n}\n```\nThat is all.", Netdown},
		{"second object has no fault", "{\"fault\":\"hang_early\"}\nand the tokens: {\"tokens\": 1200}", HangEarly},
	} {
		v, err := parseVerdict([]byte(c.out))
		if err != nil || v.Fault != c.want {
			t.Errorf("%s: %+v, %v; want %s", c.name, v, err, c.want)
		}
	}
}
