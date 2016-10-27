package pgp

import (
	"github.com/emersion/go-imap/backend"
)

type user struct {
	backend.User
}

func (u *user) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	if mailboxes, err := u.User.ListMailboxes(subscribed); err != nil {
		return nil, err
	} else {
		for i, m := range mailboxes {
			mailboxes[i] = &mailbox{m}
		}
		return mailboxes, nil
	}
}

func (u *user) GetMailbox(name string) (backend.Mailbox, error) {
	if m, err := u.User.GetMailbox(name); err != nil {
		return nil, err
	} else {
		return &mailbox{m}, nil
	}
}
