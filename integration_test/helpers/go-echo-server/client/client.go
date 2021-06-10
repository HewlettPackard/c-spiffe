package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	socketPath = "unix:///tmp/agent.sock"
	serverPort = "4433"
)

func main() {
	// Setup context
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Allowed SPIFFE ID
	spiffeID := spiffeid.Must("example.org", "myworkloadB")

	//hostname for server passed as argument
	serverAddress := os.Args[2] + ":" + serverPort

	// Create a TLS connection.
	// The client expects the server to present an SVID with the spiffeID: 'spiffe://example.org/server'
	//
	// An alternative when creating Dial is using `spiffetls.Dial` that uses environment variable `SPIFFE_ENDPOINT_SOCKET`
	conn, err := spiffetls.DialWithMode(ctx, "tcp", serverAddress,
		spiffetls.MTLSClientWithSourceOptions(
			tlsconfig.AuthorizeID(spiffeID),
			workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
		))
	if err != nil {
		log.Fatalf("could not create TLS connection: %v", err)
	}
	defer conn.Close()

	//string argv will be sent as message
	message := os.Args[1] + "\n"
	log.Printf("Client sent:     %q", message)

	// Send a message to the server using the TLS connection
	fmt.Fprint(conn, message)

	// Read server response
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		log.Fatalf("Unable to read server response: %v", err)
	}
	log.Printf("Server replied: %q", status)
}
