package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/iconidentify/maclab/internal/api"
)

// termsSum is the sha256 of labd's built-in participation terms, which a
// test's Mac accepts when it enrolls.
func termsSum() string {
	h := sha256.Sum256([]byte(DefaultTerms))
	return hex.EncodeToString(h[:])
}

// testActivationKey is the activation key of the tests' raw enrollments: one
// Mac enrolling again with it is the same activation.
const testActivationKey = "0123456789abcdef0123456789abcdef-test"

// enrollJSON is an enrollment with token, its owner having accepted the terms.
func enrollJSON(token string) string {
	b, _ := json.Marshal(api.EnrollRequest{Token: token, ActivationKey: testActivationKey, TermsSHA256: termsSum()})
	return string(b)
}
