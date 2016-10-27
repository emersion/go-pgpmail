package pgp

import (
	"bytes"
	"io"
	"log"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

type mailbox struct {
	backend.Mailbox

	u *user
}

func (m *mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []string, ch chan<- *imap.Message) error {
	// TODO: only intercept messages if fetching body parts

	messages := make(chan *imap.Message)
	go func() {
		for msg := range messages {
			for part, r := range msg.Body {
				r, err := decryptMessage(m.u.kr, r)
				if err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				b := &bytes.Buffer{}
				if _, err := io.Copy(b, r); err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				msg.Body[part] = b
			}

			ch <- msg
		}
	}()

	return m.Mailbox.ListMessages(uid, seqSet, items, messages)
}
