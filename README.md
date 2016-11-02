# go-imap-pgp

A [go-imap](https://github.com/emersion/go-imap) backend that encrypts messages
with PGP.

## Usage

This example creates a server that acts as a proxy to another server, but
automatically decrypts and encrypts messages that are downloaded and uploaded.

```go
package main

import (
	"log"

	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-imap-proxy"
	pgp "github.com/emersion/go-pgpmail/imap"
	"github.com/emersion/go-pgpmail/local"
)

func main() {
	be := pgp.New(proxy.NewTLS("mail.example.org:993", nil), local.Unlock)

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
```

## License

MIT
