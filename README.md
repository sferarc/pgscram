# pgscram

PostgreSQL SCRAM-SHA-256 verifiers in Go, with no dependencies.

```go
verifier, err := pgscram.DeriveVerifier("s3cr3t")
// SCRAM-SHA-256$4096:ri69vxV0zV9WljbYAROu7w==$Kr75...B9c=:29Hl...yfM=
```

Hand that string to PostgreSQL and it stores it as given:

```sql
CREATE ROLE app LOGIN PASSWORD 'SCRAM-SHA-256$4096:...';
```

The role can now log in with `s3cr3t`, and the password never reached the server.

## The problem this solves

PostgreSQL does not store passwords. It stores a verifier, the value in `pg_authid.rolpassword`:

```
SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
```

If you are writing anything that issues or holds PostgreSQL credentials, a connection pooler, a wire-protocol proxy, a control plane that provisions roles, a migration moving credentials between systems, you need to produce and read that string. Doing it by hand means PBKDF2, two HMACs, a SHA-256 and an encoding that has to match byte for byte or the role silently cannot log in.

## Install

```
go get github.com/sferarc/pgscram
```

Go 1.24 or later, for `crypto/pbkdf2` in the standard library.

## What it does

|  |  |
| --- | --- |
| `DeriveVerifier(password)` | Fresh random salt, PostgreSQL's default 4096 iterations, returns the encoded string. |
| `Derive(password, salt, iterations)` | Deterministic. This is what makes a verifier checkable. |
| `ParseVerifier(s)` | Reads a stored verifier. Every failure wraps `ErrInvalidVerifier`, so callers can fail closed. |
| `EncodeVerifier(v)` | The inverse. Byte identical to what PostgreSQL writes. |
| `Verifier.Matches(password)` | Constant-time check, for code holding both the verifier and the password. |

## What it does not do

**This is not a SCRAM authentication implementation.** It does not speak the challenge and response exchange of RFC 5802. It has no notion of a conversation, a nonce, a client proof or channel binding.

For the protocol, use [github.com/xdg-go/scram](https://github.com/xdg-go/scram), which implements both sides.

The two compose, and the split is worth being precise about, because `xdg-go/scram` already derives the same keys via `Client.GetStoredCredentials`. What it has no notion of is PostgreSQL's on-disk _format_: the `SCRAM-SHA-256$...` string does not appear anywhere in that package, and its parsing is entirely of protocol messages. So:

- **pgscram** produces and reads the stored verifier.
- **xdg-go/scram** runs the authentication exchange against the keys inside it.

If you are authenticating a remote client, you want both. If you are only issuing or storing credentials, this package is the whole job.

## Correctness

The derivation and the encoding are checked against PostgreSQL itself, not only against this package's own idea of the format.

A verifier taken from a running PostgreSQL 17.11 is committed as a test fixture. The suite parses it, re-derives the keys from its own salt and iteration count, and re-encodes it. All three have to match, so a systematic misreading of the format fails the build rather than shipping.

The round trip has also been exercised end to end against a live server: a verifier produced by `DeriveVerifier`, installed with `CREATE ROLE ... PASSWORD`, authenticates a real SCRAM-SHA-256 login over TCP, and the wrong password is refused.

The RFC 5802 computation is additionally written out a second time in the test suite, independently of the implementation, so a change that is internally consistent but wrong still fails.

## Dependencies

None. The standard library only.

## Contributing

Issues and pull requests are welcome here. Changes are synchronised with the repository this package is developed in, so a merged pull request travels back rather than being reapplied by hand.

The package is developed for and used in production by [PgBeam](https://pgbeam.com), which issues scoped PostgreSQL credentials to AI agents and therefore mints a great many verifiers without ever holding the passwords they stand for.

## References

- [RFC 5802](https://www.rfc-editor.org/rfc/rfc5802) (SCRAM)
- [RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) (SCRAM-SHA-256)
- [PostgreSQL password authentication](https://www.postgresql.org/docs/current/auth-password.html)

## License

Apache-2.0. See [LICENSE](./LICENSE).
