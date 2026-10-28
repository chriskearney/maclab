package workflow

import (
	"encoding/json"
	"testing"
)

func TestExistingArrayPointerBindsSelectedAssetWithoutExtension(t *testing.T) {
	var doc any
	if e := decodeValue([]byte(`{"assets":[{"sha256":null,"bytes":null,"base64":null}],"0":{"value":3}}`), &doc); e != nil {
		t.Fatal(e)
	}
	if e := set(&doc, "/assets/0/bytes", json.Number("1793026027181000123")); e != nil {
		t.Fatal(e)
	}
	v, e := get(doc, "/assets/0/bytes")
	if e != nil || v != json.Number("1793026027181000123") {
		t.Fatal(v, e)
	}
	if v, e = get(doc, "/0/value"); e != nil || v != json.Number("3") {
		t.Fatal("numeric object key changed", v, e)
	}
	for _, p := range []string{"/assets/-/bytes", "/assets/-1/bytes", "/assets/+0/bytes", "/assets/00/bytes", "/assets/1/bytes", "/assets/999999999999999999999/bytes", "/assets/0/missing", "/assets/0/bytes/scalar"} {
		if e := set(&doc, p, true); e == nil {
			t.Fatal("unsupported array mutation admitted", p)
		}
		if _, e := get(doc, p); e == nil {
			t.Fatal("unsupported array read admitted", p)
		}
	}
	if e := set(&doc, "/assets/0", map[string]any{"whole": "replacement"}); e != nil {
		t.Fatal(e)
	}
	if v, e := get(doc, "/assets/0/whole"); e != nil || v != "replacement" {
		t.Fatal(v, e)
	}
}
