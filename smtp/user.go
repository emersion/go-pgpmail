package smtp

import (
	"io"

	server "github.com/emersion/go-smtp"
	"golang.org/x/crypto/openpgp"
)

type user struct {
	server.User

	be *Backend
	kr openpgp.EntityList
}

func (u *user) Send(from string, to []string, r io.Reader) error {
	// TODO
	return nil
}
