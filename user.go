package pgp

import (
	"github.com/emersion/go-imap/backend"

	"github.com/emersion/go-imap-pgp/openpgp"
)

type user struct {
	backend.User

	kr openpgp.KeyRing
}

func (u *user) getMailbox(m backend.Mailbox) *mailbox {
	return &mailbox{m, u}
}

func (u *user) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	if mailboxes, err := u.User.ListMailboxes(subscribed); err != nil {
		return nil, err
	} else {
		for i, m := range mailboxes {
			mailboxes[i] = u.getMailbox(m)
		}
		return mailboxes, nil
	}
}

func (u *user) GetMailbox(name string) (backend.Mailbox, error) {
	if m, err := u.User.GetMailbox(name); err != nil {
		return nil, err
	} else {
		return u.getMailbox(m), nil
	}
}
