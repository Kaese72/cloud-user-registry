// Package validate holds small input-validation helpers shared across web
// apps.
package validate

import (
	"errors"
	"net/mail"
)

// Email rejects anything that isn't a single, bare RFC 5322 address - no
// display name, no comments, and critically no embedded CR/LF. Without this,
// a value like "a@b.com\r\nBcc: x@y.com" passes JSON decoding as an
// ordinary string and reaches net/smtp, which itself refuses to send it
// ("smtp: A line must not contain CR or LF") - by then the caller has
// already been told the request succeeded (registration, profile update).
func Email(s string) error {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return errors.New("invalid email address")
	}
	return nil
}
