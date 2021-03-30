package main

import (
	"crypto/tls"
	"io"
	"log"
	"os"
)

const (
	CONN_HOST = "infra_workload_1"
	CONN_PORT = "8000"
	CONN_TYPE = "tcp"
)

func main() {
	cert, err := tls.LoadX509KeyPair("../certs/client.pem", "../certs/client.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	conn, err := tls.Dial(CONN_TYPE, CONN_HOST+":"+CONN_PORT, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	//string argv will be sent as message
	message := os.Args[1]
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: sent: %s", err)
	}
	log.Printf("client: sent     %q (%d bytes)", message, n)

	reply := make([]byte, 100)
	n, err = conn.Read(reply)
	if err != nil {
		if err != io.EOF {
			log.Printf("client: read: %s", err)
		}
	}

	log.Printf("client: received %q (%d bytes)\n", string(reply[:n]), n)

	log.Print("client: exiting")
}
