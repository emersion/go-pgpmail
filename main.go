// +build ignore

package main

import (
	"log"

	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-imap-proxy"
	"github.com/emersion/go-imap-pgp"
	"github.com/emersion/go-imap-pgp/local"
)

func main() {
	be := pgp.New(proxy.NewTLS("mail.gandi.net:993", nil), local.Unlock)

	// Create a new server
	s := server.New(be)
	s.Addr = ":1143"
	// Since we will use this server for testing only, we can allow plain text
	// authentication over unencrypted connections
	s.AllowInsecureAuth = true

	log.Println("Starting IMAP server at localhost:1143")
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
