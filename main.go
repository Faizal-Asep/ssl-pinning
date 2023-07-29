package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type Dialer func(network, addr string) (net.Conn, error)

func makeDialer(fingerprints [][32]byte, skipCAVerification bool) Dialer {
	return func(network, addr string) (net.Conn, error) {
		// Read the key pair to create certificate

		c, err := tls.Dial(network, addr, &tls.Config{
			InsecureSkipVerify: skipCAVerification,
		})

		if err != nil {
			return c, err
		}
		connstate := c.ConnectionState()
		// fmt.Println("keyPinValid")
		keyPinValid := false
		for _, peercert := range connstate.PeerCertificates {
			der, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
			hash := sha256.Sum256(der)
			if err != nil {
				log.Fatal(err)
			}
			for _, fingerprint := range fingerprints {
				if bytes.Equal(hash[0:], fingerprint[0:]) {
					keyPinValid = true
					break
				}
			}
		}

		if !keyPinValid {
			return c, errors.New(" Pinned Key not found")
		}
		return c, nil
	}
}

func main() {
	start := time.Now()
	// Create a HTTPS client and supply the created CA pool and certificate
	fingerprints := [][32]byte{
		{0xb3, 0xec, 0x54, 0x95, 0xc6, 0x94, 0x63, 0x72, 0x5f, 0x63, 0xa0, 0x1, 0x8d, 0x20, 0x10, 0xd, 0xd5, 0x17, 0x96, 0x45, 0x14, 0xb6, 0x0, 0xe0, 0x85, 0x6e, 0x92, 0x75, 0x4e, 0xc6, 0xc2, 0xb},
		{0xcc, 0x24, 0xe7, 0x7c, 0xbc, 0xb, 0x29, 0xb4, 0xbd, 0x4b, 0x6b, 0x1b, 0xa7, 0xeb, 0x85, 0xcf, 0x82, 0x99, 0x3a, 0x87, 0x5, 0xbd, 0x7c, 0x64, 0x57, 0x4e, 0x82, 0x7b, 0xd3, 0xb9, 0x33, 0x6c},
		{0x87, 0x1a, 0x91, 0x94, 0xf4, 0xee, 0xd5, 0xb3, 0x12, 0xff, 0x40, 0xc8, 0x4c, 0x1d, 0x52, 0x4a, 0xed, 0x2f, 0x77, 0x8b, 0xbf, 0xf2, 0x5f, 0x13, 0x8c, 0xf8, 0x1f, 0x68, 0xa, 0x7a, 0xdc, 0x67},
	}

	// fmt.Println(base64.StdEncoding.EncodeToString(fingerprint[0:]))
	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: makeDialer(fingerprints, false),
		},
	}

	r, err := client.Get("https://www.google.com")
	if err != nil {
		log.Fatal(err)
	}
	// Read the response body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	// Print the response body to stdout
	fmt.Printf("%s\n", body)
	fmt.Println("Duration : ", time.Since(start))
}
