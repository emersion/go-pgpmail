package smtp

import (
	server "github.com/emersion/go-smtp-server"
	"golang.org/x/crypto/openpgp"
)

type user struct {
	server.User

	be *Backend
	kr openpgp.EntityList
}

func (u *user) Send(msg *server.Message) error {
	// TODO
	return nil
}
