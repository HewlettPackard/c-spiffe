package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const jwks = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "RSA",
            "n": "3CErJbXU-LId44PrDxBbkys8mqb6-DpwVIsTJtMpY0j7Y5l05efthP4rF0VRh5uZr7GBkkkeBtHjE53P353ODDiwq70LTfqsVtcDuMMY_GYwAB3iHgJ0ubweARBWjRUHxQxSkjDKhdXI5BYDKYvAoERly3BAmsEWvQkMiUbkoRE2tnS3qOcGfPy9xWF_XJkgnMshRLp6bxyYpkFJEDpnLrslQYsunFUcYIP9B0AUyYADM5S-G0OwwFjtW6J4VHtJFIkFjS5qpmAEVO6cOMmhi3bvJGUw2Ns3xbwWLj0UCMll5kFXnH608P_Vwgpy0P0fTJ1CNvsRyJUDGTZGeOujpw",
            "e": "AQAB",
            "x5c": [
                "MIID8zCCAtugAwIBAgIUc1IscvOYvHFCpp1qoIA3giuEyakwDQYJKoZIhvcNAQELBQAwNDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwIBcNMjEwNTI3MTQ0NDU0WhgPMjEyMTA1MDMxNDQ0NTRaMDQxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUxFDASBgNVBAMMC2V4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CErJbXU+LId44PrDxBbkys8mqb6+DpwVIsTJtMpY0j7Y5l05efthP4rF0VRh5uZr7GBkkkeBtHjE53P353ODDiwq70LTfqsVtcDuMMY/GYwAB3iHgJ0ubweARBWjRUHxQxSkjDKhdXI5BYDKYvAoERly3BAmsEWvQkMiUbkoRE2tnS3qOcGfPy9xWF/XJkgnMshRLp6bxyYpkFJEDpnLrslQYsunFUcYIP9B0AUyYADM5S+G0OwwFjtW6J4VHtJFIkFjS5qpmAEVO6cOMmhi3bvJGUw2Ns3xbwWLj0UCMll5kFXnH608P/Vwgpy0P0fTJ1CNvsRyJUDGTZGeOujpwIDAQABo4H6MIH3MAkGA1UdEwQCMAAwKAYDVR0RBCEwH4Ydc3BpZmZlOi8vZXhhbXBsZS5vcmcvd29ya2xvYWQwHQYDVR0OBBYEFCfcXfUrUp7s7RfshCkSEnW0mAlbMG8GA1UdIwRoMGaAFFkJY/1Dl7/xxDfHAO0enNmsxUKQoTikNjA0MQswCQYDVQQGEwJVUzEPMA0GA1UECgwGU1BJRkZFMRQwEgYDVQQDDAtleGFtcGxlLm9yZ4IUX2ap2e4rmTrPAQM/A4P6ojCg+5gwDgYDVR0PAQH/BAQDAgOoMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAx1mwKx6BUTwQvzX5doRtCC5++oTL9ogrmY38bydQosIHu4KIO6AQi2qcENXVPIoqykP+hzxIBqZDd0VElKFiJz72hv9Y9Qpy2SSsKK0/pNHb91aM4XtsUfqloPt9I/kfSdWOhFkT3u5fhFyG8sE3i2BT8vjxmFXPkqGD9q5V2kd2aSaLPZNIPfsvCz5BoGfsly/YAqhJLHW5oU2CtujV+0lrCEpI9myPVSu/DiCfODj250CqHgfsla7n9vvMdRZlOHBqrhl2XwgixkGinM3aF1T5QnptJBepVgwr10BEzU+tCMbACkF+Of4uS+ssTRjwaY98JanPGsHqi0stikSplw=="
            ]
        },
        {
            "use": "x509-svid",
            "kty": "RSA",
            "n": "0mfowcVtUL-Qkf8ommz-afivIXJiV1emoZ199b1CDXEiGR5_ordFvz6y4l8_q6i0psKIhYaag56nTUSk5kjcUJpzuVkVV5vdG3IVLo4n3ULbZEjZEnorWlhYJcAJLNJhYk6An32uz4-pjlzigSxghinUBFG8e5A-etAST6VZ8HtIWErjEe92R8paB56IACwzbhFpJ_OTQu6FJNiRf5XDipMf6whXFwmwEws-FiZa-m5-4zE-QSWxS1WmJM4qAJsCcCJDvuc7_6JoF8Y7O6wsIVZ0vvg1f26caXG80bYBSF_xX6gcSgFa0OvrMauVNFIbVKZkdOgdjftOPvni7OpIUQ",
            "e": "AQAB",
            "x5c": [
                "MIIDUjCCAjqgAwIBAgIUX2ap2e4rmTrPAQM/A4P6ojCg+5gwDQYJKoZIhvcNAQEFBQAwNDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwIBcNMjEwNTI3MTQ0NDM5WhgPMjEyMTA1MDMxNDQ0MzlaMDQxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZTUElGRkUxFDASBgNVBAMMC2V4YW1wbGUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0mfowcVtUL+Qkf8ommz+afivIXJiV1emoZ199b1CDXEiGR5/ordFvz6y4l8/q6i0psKIhYaag56nTUSk5kjcUJpzuVkVV5vdG3IVLo4n3ULbZEjZEnorWlhYJcAJLNJhYk6An32uz4+pjlzigSxghinUBFG8e5A+etAST6VZ8HtIWErjEe92R8paB56IACwzbhFpJ/OTQu6FJNiRf5XDipMf6whXFwmwEws+FiZa+m5+4zE+QSWxS1WmJM4qAJsCcCJDvuc7/6JoF8Y7O6wsIVZ0vvg1f26caXG80bYBSF/xX6gcSgFa0OvrMauVNFIbVKZkdOgdjftOPvni7OpIUQIDAQABo1owWDAJBgNVHRMEAjAAMB8GA1UdEQQYMBaGFHNwaWZmZTovL2V4YW1wbGUuY29tMB0GA1UdDgQWBBRZCWP9Q5e/8cQ3xwDtHpzZrMVCkDALBgNVHQ8EBAMCB4AwDQYJKoZIhvcNAQEFBQADggEBAAJOA81nY/8ItGUO2BZey6wnH88fnTwmum2XG/uzUeYIuGMztUuoGzQ5bpOVhh8Fe9O3biJ1u+zJzRWO6J4XuMWkjGCGp6oYvnwXxvd6nas1HkqEH7q/4hgX4CtHUAWnW5sa8t2jbG+a5x7534ZZQ5VwMZXTm07wAMtRVTqRYl6nSHUWCDowZjqR02tJRtGbSia04tq17ojcdIa7mVrrfFU1Frn3kCh6ifyIk9lOVhhR3B4evyOuanLPUjj8QHR7yPTxtDsBQ+FGwhC9W7hAaMcu7k8iy8ASaqM2w4bCUPpiQWm6kVeHUbr7jEoB/Ym87fInIorVFysctktK2pSlcgU="
            ]
        }
    ],
    "spiffe_refresh_hint": 60
}
`

type fakeSource struct {
	bundles map[spiffeid.TrustDomain]*spiffebundle.Bundle
}

func (s *fakeSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	b, ok := s.bundles[trustDomain]
	if !ok {
		return nil, errors.New("bundle not found")
	}
	return b, nil
}

func main() {
	var address string = "127.0.0.1:433"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	// generate a `Certificate` struct
	cert, _ := tls.LoadX509KeyPair("./resources/example.org.crt", "./resources/example.org.key")
	trustDomain, _ := spiffeid.TrustDomainFromString("example.org")
	bundle, _ := spiffebundle.Parse(trustDomain, []byte(jwks))
	source := &fakeSource{}
	source.bundles = map[spiffeid.TrustDomain]*spiffebundle.Bundle{
		trustDomain: bundle,
	}
	writer := new(bytes.Buffer)
	handler := federation.Handler(trustDomain, source, logger.Writer(writer))
	// create a custom server with `TLSConfig`
	s := &http.Server{
		Addr:    address,
		Handler: handler, // use `http.DefaultServeMux`
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// run server on port "443"
	log.Fatal(s.ListenAndServeTLS("", ""))

}
