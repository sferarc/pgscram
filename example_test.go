package pgscram_test

import (
	"fmt"
	"log"

	"github.com/sferarc/pgscram"
)

// Issuing a credential without ever storing the password: derive a verifier and
// hand it to PostgreSQL, which stores a well-formed one verbatim rather than
// re-hashing it.
func ExampleDeriveVerifier() {
	verifier, err := pgscram.DeriveVerifier("s3cr3t")
	if err != nil {
		log.Fatal(err)
	}

	// Safe to interpolate: the value is base64 and digits, and PostgreSQL
	// accepts it in place of a password.
	fmt.Printf("CREATE ROLE app LOGIN PASSWORD '%s';\n", verifier[:14]+"...")
	// Output: CREATE ROLE app LOGIN PASSWORD 'SCRAM-SHA-256$...';
}

// Reading what PostgreSQL stored. The string is the one in
// pg_authid.rolpassword.
func ExampleParseVerifier() {
	const stored = "SCRAM-SHA-256$4096:ri69vxV0zV9WljbYAROu7w==$" +
		"Kr7535LzVPp4amH+iuBEfvpKw5iUZcAnzcBXcSnrB9c=:" +
		"29Hli33Ue/4f5x+9YxUcgc5C8xWbTGI+lpG3TDTcyfM="

	v, err := pgscram.ParseVerifier(stored)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("iterations:", v.Iterations)
	fmt.Println("salt bytes:", len(v.Salt))
	fmt.Println("password is correct-horse:", v.Matches("correct-horse"))
	// Output:
	// iterations: 4096
	// salt bytes: 16
	// password is correct-horse: true
}

// Derive is the deterministic form, which is what makes a verifier checkable:
// parse one, derive again from its own salt and iteration count, and compare.
func ExampleDerive() {
	salt := []byte("0123456789abcdef")

	v, err := pgscram.Derive("correct-horse", salt, pgscram.DefaultIterations)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pgscram.EncodeVerifier(v))
	// Output: SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$mczM2ZSmTTZel/Twoj/nBkAiqs7JRsrB7NAWGR8ADVE=:AQsoihmXc3pHuyM4Kz66fiF+T+VAj31sRAXfAnTO+B0=
}
