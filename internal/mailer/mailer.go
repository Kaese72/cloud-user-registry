// Package mailer sends transactional email over SMTP, currently just the
// password reset link. It is deliberately minimal: a single plain-text
// message via net/smtp, relying on the configured relay for STARTTLS and
// authentication.
package mailer

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/Kaese72/cloud-user-registry/internal/config"
)

type Mailer struct {
	conf config.SMTPConfig
}

func New(conf config.SMTPConfig) Mailer {
	return Mailer{conf: conf}
}

func (m Mailer) send(to string, subject string, body string) error {
	addr := fmt.Sprintf("%s:%d", m.conf.Host, m.conf.Port)
	var auth smtp.Auth
	if m.conf.Username != "" {
		auth = smtp.PlainAuth("", m.conf.Username, m.conf.Password, m.conf.Host)
	}
	msg := strings.Join([]string{
		"From: " + m.conf.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=\"UTF-8\"",
		"",
		body,
	}, "\r\n")
	return smtp.SendMail(addr, auth, m.conf.From, []string{to}, []byte(msg))
}

// SendPasswordReset emails a link, built from resetURL, that lets the
// recipient set a new password. The link is expected to already contain
// the reset token as a query parameter.
func (m Mailer) SendPasswordReset(to string, resetURL string) error {
	body := fmt.Sprintf(
		"We received a request to reset the password for your Humi Cloud account.\r\n\r\n"+
			"To choose a new password, open the link below. It expires shortly after this email was sent.\r\n\r\n"+
			"%s\r\n\r\n"+
			"If you did not request this, you can safely ignore this email.\r\n",
		resetURL,
	)
	return m.send(to, "Reset your Humi Cloud password", body)
}
