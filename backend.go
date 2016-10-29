package pgp

import (
	"github.com/emersion/go-imap/backend"

	"golang.org/x/crypto/openpgp"
)

type UnlockFunction func(username, password string) (openpgp.EntityList, error)

func UnlockRemember(f UnlockFunction) UnlockFunction {
	cache := map[string]openpgp.EntityList{}
	return func(username, password string) (openpgp.EntityList, error) {
		if kr, ok := cache[username]; ok {
			return kr, nil
		}

		kr, err := f(username, password)
		if err != nil {
			return nil, err
		}

		cache[username] = kr
		return kr, nil
	}
}

type Backend struct {
	backend.Backend

	unlock UnlockFunction
}

func New(be backend.Backend, unlock UnlockFunction) *Backend {
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
