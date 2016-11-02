// +build ignore

package main

import (
	"log"

	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-imap-proxy"
	"github.com/emersion/go-pgpmail"
	pgpimap "github.com/emersion/go-pgpmail/imap"
	"github.com/emersion/go-pgpmail/local"
)

func main() {
	be := pgpimap.New(proxy.NewTLS("mail.gandi.net:993", nil), pgpmail.UnlockRemember(pgpmail.UnlockSync(local.Unlock)))

	// Create a new server
	s := server.New(be)
	s.Addr = ":1143"
	// Since we will use this server for testing only, we can allow plain text
	// authentication over unencrypted connections
	s.AllowInsecureAuth = true

	log.Println("Starting IMAP server at "+s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
