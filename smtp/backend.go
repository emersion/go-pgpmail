// Package smtp provides a go-smtp-server backend that encrypts messages with
// PGP.
package smtp

import (
	"github.com/emersion/go-pgp-pubkey"
	server "github.com/emersion/go-smtp"
	"golang.org/x/crypto/openpgp"
)

type KeyRing interface {
	pubkey.Source
	Unlock(username, password string) (openpgp.EntityList, error)
}

type Backend struct {
	server.Backend

	kr KeyRing
}

func New(be server.Backend, kr KeyRing) *Backend {
	return &Backend{be, kr}
}

func (be *Backend) Login(username, password string) (server.User, error) {
	if u, err := be.Backend.Login(username, password); err != nil {
		return nil, err
	} else if kr, err := be.kr.Unlock(username, password); err != nil {
		return nil, err
	} else {
		return &user{u, be, kr}, nil
	}
}
