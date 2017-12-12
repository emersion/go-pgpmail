package imap

import (
	"bytes"
	"io"
	"log"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

type mailbox struct {
	backend.Mailbox

	u *user
}

func (m *mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	// TODO: support imap.BodySectionName.Partial
	// TODO: support imap.TextSpecifier

	// Only intercept messages if fetching body parts
	needsDecryption := false
	for _, item := range items {
		if _, err := imap.ParseBodySectionName(item); err == nil {
			needsDecryption = true
			break
		}
	}
	if !needsDecryption {
		return m.Mailbox.ListMessages(uid, seqSet, items, ch)
	}

	messages := make(chan *imap.Message)
	go func() {
		defer close(ch)

		for msg := range messages {
			for section, literal := range msg.Body {
				if section.Specifier != imap.EntireSpecifier {
					continue
				}

				r, err := decryptMessage(m.u.kr, literal)
				if err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				b := new(bytes.Buffer)
				if _, err := io.Copy(b, r); err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				msg.Body[section] = b
			}

			ch <- msg
		}
	}()

	return m.Mailbox.ListMessages(uid, seqSet, items, messages)
}

func (m *mailbox) CreateMessage(flags []string, date time.Time, r imap.Literal) error {
	b := new(bytes.Buffer)
	if err := encryptMessage(m.u.kr, b, r); err != nil {
		return err
	}

	return m.Mailbox.CreateMessage(flags, date, b)
}
