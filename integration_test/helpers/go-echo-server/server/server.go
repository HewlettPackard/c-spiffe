package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
)

const (
	CONN_HOST = "0.0.0.0"
	CONN_PORT = "8000"
	CONN_TYPE = "tcp"
)

func main() {
	cert, err := tls.LoadX509KeyPair("../certs/server.pem", "../certs/server.key")

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	listener, err := tls.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening on port ", CONN_PORT)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s -> %s \n", conn.RemoteAddr(), conn.LocalAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		// Handle connections in a new goroutine.
		go handleClient(conn)
	}
}

// Handles incoming requests.
func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 100)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}

		log.Printf("server: conn: received %q (%d bytes)\n", string(buf[:n]), n)

		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: replied  %q (%d bytes)", string(buf[:n]), n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
