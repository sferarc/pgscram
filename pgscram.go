package pgscram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultIterations is the PBKDF2 iteration count used when deriving a new
// verifier. It matches the PostgreSQL default (4096), so a verifier produced
// here is indistinguishable from one PostgreSQL would have written for the
// same password.
const DefaultIterations = 4096

// SaltLen is the number of random salt bytes DeriveVerifier uses. PostgreSQL
// uses the same length, which is why a verifier from either side round trips
// through the other unchanged.
const SaltLen = 16

// ErrInvalidVerifier indicates a stored verifier string could not be parsed in
// the expected SCRAM-SHA-256 format. Every parse failure wraps it, so a caller
// can fail closed on errors.Is without matching on message text.
var ErrInvalidVerifier = errors.New("invalid SCRAM-SHA-256 verifier")

// Verifier is the parsed form of a stored SCRAM-SHA-256 secret. StoredKey and
// ServerKey are derived from the password; the cleartext password is never
// retained. A server verifies a client by recomputing the client proof against
// StoredKey, and proves itself to the client with ServerKey.
type Verifier struct {
	Iterations int
	Salt       []byte
	StoredKey  []byte
	ServerKey  []byte
}

// DeriveVerifier computes a SCRAM-SHA-256 verifier from a cleartext password
// using a fresh random salt and DefaultIterations, and returns it in the
// PostgreSQL on-disk encoding.
//
// The result can be handed to PostgreSQL verbatim:
//
//	CREATE ROLE app LOGIN PASSWORD '<the returned string>'
//
// PostgreSQL stores a well-formed verifier as given rather than re-hashing it,
// so the password never reaches the server.
//
// It returns an error only if the system random source fails.
func DeriveVerifier(password string) (string, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate scram salt: %w", err)
	}
	v, err := Derive(password, salt, DefaultIterations)
	if err != nil {
		return "", err
	}
	return EncodeVerifier(v), nil
}

// Derive computes a Verifier from a password, an explicit salt and an explicit
// iteration count, per RFC 5802. Unlike DeriveVerifier it is deterministic,
// which is what makes it useful for checking an existing verifier: parse one,
// derive again from its own salt and iterations, and compare.
//
// It returns an error for an iteration count below 1 or an empty salt, both of
// which PostgreSQL would refuse.
func Derive(password string, salt []byte, iterations int) (Verifier, error) {
	if iterations < 1 {
		return Verifier{}, fmt.Errorf("%w: iteration count must be at least 1", ErrInvalidVerifier)
	}
	if len(salt) == 0 {
		return Verifier{}, fmt.Errorf("%w: salt must not be empty", ErrInvalidVerifier)
	}

	// PBKDF2 is the only step that can fail, and only for parameters this
	// function has already rejected. The error is still returned rather than
	// discarded, because swallowing it would make a future parameter change
	// silently produce a wrong key instead of an error.
	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return Verifier{}, fmt.Errorf("derive salted password: %w", err)
	}

	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))

	return Verifier{
		Iterations: iterations,
		Salt:       salt,
		StoredKey:  storedKey[:],
		ServerKey:  serverKey,
	}, nil
}

// Matches reports whether password is the one this verifier was derived from.
// The comparison is constant time with respect to StoredKey.
//
// This is a convenience for code that holds both the verifier and the
// cleartext password, such as a proxy validating a credential it just issued.
// It is NOT how a SCRAM server authenticates a remote client: in the protocol
// the server never sees the password, and checks a client proof against
// StoredKey instead. Use github.com/xdg-go/scram for that exchange.
func (v Verifier) Matches(password string) bool {
	got, err := Derive(password, v.Salt, v.Iterations)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got.StoredKey, v.StoredKey) == 1
}

// EncodeVerifier renders a Verifier in the PostgreSQL on-disk format.
func EncodeVerifier(v Verifier) string {
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		v.Iterations,
		b64(v.Salt),
		b64(v.StoredKey),
		b64(v.ServerKey),
	)
}

// ParseVerifier parses a stored SCRAM-SHA-256 verifier string, the value found
// in pg_authid.rolpassword. It returns ErrInvalidVerifier (wrapped) for any
// malformed input so callers can fail closed.
func ParseVerifier(s string) (Verifier, error) {
	const prefix = "SCRAM-SHA-256$"
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return Verifier{}, fmt.Errorf("%w: missing mechanism prefix", ErrInvalidVerifier)
	}

	iterSalt, keys, ok := strings.Cut(rest, "$")
	if !ok {
		return Verifier{}, fmt.Errorf("%w: missing key section", ErrInvalidVerifier)
	}

	iterStr, saltB64, ok := strings.Cut(iterSalt, ":")
	if !ok {
		return Verifier{}, fmt.Errorf("%w: missing salt", ErrInvalidVerifier)
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations <= 0 {
		return Verifier{}, fmt.Errorf("%w: bad iteration count", ErrInvalidVerifier)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return Verifier{}, fmt.Errorf("%w: bad salt encoding", ErrInvalidVerifier)
	}

	storedB64, serverB64, ok := strings.Cut(keys, ":")
	if !ok {
		return Verifier{}, fmt.Errorf("%w: missing server key", ErrInvalidVerifier)
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedB64)
	if err != nil {
		return Verifier{}, fmt.Errorf("%w: bad stored key encoding", ErrInvalidVerifier)
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverB64)
	if err != nil {
		return Verifier{}, fmt.Errorf("%w: bad server key encoding", ErrInvalidVerifier)
	}

	return Verifier{
		Iterations: iterations,
		Salt:       salt,
		StoredKey:  storedKey,
		ServerKey:  serverKey,
	}, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
