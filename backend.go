package pgp

import (
	"github.com/emersion/go-imap/backend"
)

type Backend struct {
	backend.Backend
}

func New(be backend.Backend) *Backend {
	return &Backend{be}
}

func (be *Backend) Login(username, password string) (backend.User, error) {
	if u, err := be.Backend.Login(username, password); err != nil {
		return nil, err
	} else {
		return &user{u}, nil
	}
}
