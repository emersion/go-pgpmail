// Package imap provides a go-imap backend that encrypts and decrypts PGP
// messages.
package imap

import (
	"github.com/emersion/go-imap/backend"

	"github.com/emersion/go-pgpmail"
)

type Backend struct {
	backend.Backend

	unlock pgpmail.UnlockFunction
}

func New(be backend.Backend, unlock pgpmail.UnlockFunction) *Backend {
	return &Backend{be, unlock}
}

func (be *Backend) Login(username, password string) (backend.User, error) {
	if u, err := be.Backend.Login(username, password); err != nil {
		return nil, err
	} else if kr, err := be.unlock(username, password); err != nil {
		return nil, err
	} else {
		return &user{u, kr}, nil
	}
}
