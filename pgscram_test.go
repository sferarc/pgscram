package pgscram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// postgresVerifier is a verifier taken from a running PostgreSQL 17.11, for the
// role created by:
//
//	CREATE ROLE scramprobe LOGIN PASSWORD 'correct-horse';
//	SELECT rolpassword FROM pg_authid WHERE rolname = 'scramprobe';
//
// It is the load-bearing test in this package. Every other test checks this
// code against itself, which cannot catch a systematic misreading of the
// format. This one is ground truth produced by the software we claim to be
// interchangeable with, so if the derivation or the encoding ever drifts from
// PostgreSQL's, this is what notices.
const (
	postgresVerifier = "SCRAM-SHA-256$4096:ri69vxV0zV9WljbYAROu7w==$" +
		"Kr7535LzVPp4amH+iuBEfvpKw5iUZcAnzcBXcSnrB9c=:" +
		"29Hli33Ue/4f5x+9YxUcgc5C8xWbTGI+lpG3TDTcyfM="
	postgresPassword = "correct-horse"
)

// TestMatchesPostgreSQL is the interchangeability claim, checked in both
// directions: PostgreSQL's verifier parses here, re-derives to the same keys
// from its own salt, and re-encodes to the identical string.
func TestMatchesPostgreSQL(t *testing.T) {
	t.Parallel()

	v, err := ParseVerifier(postgresVerifier)
	if err != nil {
		t.Fatalf("ParseVerifier on a real PostgreSQL verifier: %v", err)
	}

	if v.Iterations != DefaultIterations {
		t.Errorf("iterations = %d, want %d (PostgreSQL's default)", v.Iterations, DefaultIterations)
	}
	if len(v.Salt) != SaltLen {
		t.Errorf("salt length = %d, want %d (PostgreSQL's salt length)", len(v.Salt), SaltLen)
	}

	got, err := Derive(postgresPassword, v.Salt, v.Iterations)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if !hmac.Equal(got.StoredKey, v.StoredKey) {
		t.Error("StoredKey does not match the one PostgreSQL derived for this password")
	}
	if !hmac.Equal(got.ServerKey, v.ServerKey) {
		t.Error("ServerKey does not match the one PostgreSQL derived for this password")
	}

	if enc := EncodeVerifier(v); enc != postgresVerifier {
		t.Errorf("re-encoding is not byte identical to PostgreSQL's:\n got %q\nwant %q", enc, postgresVerifier)
	}
}

// TestMatchesAgainstPostgreSQLVerifier exercises the password check against the
// same ground truth, in both the positive and the negative direction.
func TestMatchesAgainstPostgreSQLVerifier(t *testing.T) {
	t.Parallel()

	v, err := ParseVerifier(postgresVerifier)
	if err != nil {
		t.Fatalf("ParseVerifier: %v", err)
	}
	if !v.Matches(postgresPassword) {
		t.Error("Matches rejected the password PostgreSQL derived this verifier from")
	}
	if v.Matches("correct-horse ") {
		t.Error("Matches accepted a password differing by one trailing space")
	}
	if v.Matches("") {
		t.Error("Matches accepted an empty password")
	}
}

func TestDeriveAndParseRoundTrip(t *testing.T) {
	t.Parallel()

	enc, err := DeriveVerifier("s3cr3t-password")
	if err != nil {
		t.Fatalf("DeriveVerifier: %v", err)
	}
	if !strings.HasPrefix(enc, "SCRAM-SHA-256$") {
		t.Fatalf("unexpected encoding prefix: %q", enc)
	}

	v, err := ParseVerifier(enc)
	if err != nil {
		t.Fatalf("ParseVerifier: %v", err)
	}
	if v.Iterations != DefaultIterations {
		t.Errorf("iterations = %d, want %d", v.Iterations, DefaultIterations)
	}
	if len(v.Salt) != SaltLen {
		t.Errorf("salt len = %d, want %d", len(v.Salt), SaltLen)
	}
	if len(v.StoredKey) != sha256.Size || len(v.ServerKey) != sha256.Size {
		t.Errorf("key lengths: stored=%d server=%d", len(v.StoredKey), len(v.ServerKey))
	}
	if !v.Matches("s3cr3t-password") {
		t.Error("a verifier does not match the password it was just derived from")
	}
}

// TestDerivedKeysMatchRFC writes out the RFC 5802 computation separately from
// the implementation, so a change to Derive that is self consistent but wrong
// still fails here.
func TestDerivedKeysMatchRFC(t *testing.T) {
	t.Parallel()

	const password = "correct-horse"
	enc, err := DeriveVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseVerifier(enc)
	if err != nil {
		t.Fatal(err)
	}

	salted, err := pbkdf2.Key(sha256.New, password, v.Salt, v.Iterations, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	wantStored := sha256.Sum256(clientKey)
	wantServer := hmacSHA256(salted, []byte("Server Key"))

	if !hmac.Equal(v.StoredKey, wantStored[:]) {
		t.Error("StoredKey does not match RFC derivation")
	}
	if !hmac.Equal(v.ServerKey, wantServer) {
		t.Error("ServerKey does not match RFC derivation")
	}
}

func TestParseVerifierRejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":                 "",
		"plaintext":             "plaintext",
		"prefix only":           "SCRAM-SHA-256$",
		"no key section":        "SCRAM-SHA-256$4096",
		"salt not base64":       "SCRAM-SHA-256$4096:notbase64!$a:b",
		"iterations not a int":  "SCRAM-SHA-256$abc:c2FsdA==$a:b",
		"wrong mechanism":       "MD5$4096:c2FsdA==$a:b",
		"zero iterations":       "SCRAM-SHA-256$0:c2FsdA==$YQ==:Yg==",
		"negative iterations":   "SCRAM-SHA-256$-1:c2FsdA==$YQ==:Yg==",
		"missing server key":    "SCRAM-SHA-256$4096:c2FsdA==$YQ==",
		"stored key not base64": "SCRAM-SHA-256$4096:c2FsdA==$!!!:Yg==",
		"server key not base64": "SCRAM-SHA-256$4096:c2FsdA==$YQ==:!!!",
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseVerifier(c); !errors.Is(err, ErrInvalidVerifier) {
				t.Errorf("ParseVerifier(%q) err = %v, want ErrInvalidVerifier", c, err)
			}
		})
	}
}

func TestDeriveRejectsDegenerateParameters(t *testing.T) {
	t.Parallel()

	if _, err := Derive("pw", []byte("salt"), 0); !errors.Is(err, ErrInvalidVerifier) {
		t.Errorf("Derive with zero iterations err = %v, want ErrInvalidVerifier", err)
	}
	if _, err := Derive("pw", []byte("salt"), -1); !errors.Is(err, ErrInvalidVerifier) {
		t.Errorf("Derive with negative iterations err = %v, want ErrInvalidVerifier", err)
	}
	if _, err := Derive("pw", nil, DefaultIterations); !errors.Is(err, ErrInvalidVerifier) {
		t.Errorf("Derive with a nil salt err = %v, want ErrInvalidVerifier", err)
	}
}

func TestDeriveVerifierUsesFreshSalt(t *testing.T) {
	t.Parallel()

	a, err := DeriveVerifier("same")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveVerifier("same")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two derivations of the same password produced identical verifiers (salt not random)")
	}
}

// TestDeriveIsDeterministic is the counterpart: given the same salt, the answer
// must not move, or the round trip in TestMatchesPostgreSQL means nothing.
func TestDeriveIsDeterministic(t *testing.T) {
	t.Parallel()

	salt := []byte("0123456789abcdef")
	a, err := Derive("pw", salt, DefaultIterations)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive("pw", salt, DefaultIterations)
	if err != nil {
		t.Fatal(err)
	}
	if EncodeVerifier(a) != EncodeVerifier(b) {
		t.Error("Derive is not deterministic for a fixed salt")
	}
}
