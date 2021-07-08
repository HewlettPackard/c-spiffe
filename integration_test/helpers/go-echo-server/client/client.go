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
)

func main() {
	// Setup context
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Allowed SPIFFE ID
	//trust domain and workload id passed as arguments
	spiffeID := spiffeid.Must(os.Args[4], os.Args[5])

	//hostname and port for server passed as arguments
	serverAddress := os.Args[2] + ":" + os.Args[3]

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
