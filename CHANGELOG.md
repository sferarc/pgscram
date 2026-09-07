# Changelog

## v0.1.0

First release.

- `DeriveVerifier`, `Derive`, `ParseVerifier`, `EncodeVerifier` and `Verifier.Matches`.
- Checked against a verifier from a running PostgreSQL 17.11, and against an independent transcription of the RFC 5802 derivation.
- No dependencies. Requires Go 1.24 for `crypto/pbkdf2`.
