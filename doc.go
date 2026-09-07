// Package pgscram derives, encodes and parses SCRAM-SHA-256 verifiers in the
// PostgreSQL on-disk format.
//
// A PostgreSQL role's password is stored as a verifier, not as the password:
//
//	SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
//
// This is the value in pg_authid.rolpassword, and the value PostgreSQL accepts
// verbatim in CREATE ROLE ... PASSWORD and ALTER ROLE ... PASSWORD. A server
// holding one can authenticate a client and prove itself back to that client
// without ever holding the cleartext password.
//
// # What this package is for
//
// Anything that stores or issues PostgreSQL credentials without wanting the
// password itself: a connection pooler, a wire-protocol proxy, a control plane
// that provisions roles, a migration that moves credentials between systems.
//
// # What this package is not
//
// It is not a SCRAM authentication implementation. It does not speak the
// challenge and response exchange of RFC 5802, and it has no notion of a
// conversation, a nonce or channel binding. For that, use
// github.com/xdg-go/scram, which implements the protocol on both sides.
//
// The two compose. This package produces and reads the stored verifier;
// xdg-go/scram runs the exchange against the keys inside it.
//
// # Correctness
//
// The derivation is checked two ways in the test suite. Against a verifier
// taken from a running PostgreSQL 17.11, which this package parses, re-derives
// from the same password and salt, and re-encodes byte for byte. And against
// the RFC 5802 computation written out independently.
//
// The round trip has also been exercised end to end: a verifier produced here,
// installed with CREATE ROLE ... PASSWORD, authenticates a real
// SCRAM-SHA-256 login, and the wrong password is refused.
//
// # Dependencies
//
// None. The standard library only, using crypto/pbkdf2 from Go 1.24.
//
// See RFC 5802 (SCRAM) and RFC 7677 (SCRAM-SHA-256).
package pgscram
