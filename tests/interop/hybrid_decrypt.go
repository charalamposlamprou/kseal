//go:build ignore

// Decrypts a kseal-sealed value with the same Go primitives sealed-secrets'
// pkg/crypto.HybridDecrypt uses. Usage: go run hybrid_decrypt.go KEY.pem LABEL B64
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
)

func must(err error) {
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func main() {
	keyPEM, err := os.ReadFile(os.Args[1])
	must(err)
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	must(err)
	ct, err := base64.StdEncoding.DecodeString(os.Args[3])
	must(err)

	n := int(binary.BigEndian.Uint16(ct))
	rsaCT, aesCT := ct[2:2+n], ct[2+n:]
	session, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, rsaCT, []byte(os.Args[2]))
	must(err)
	blk, err := aes.NewCipher(session)
	must(err)
	aed, err := cipher.NewGCM(blk)
	must(err)
	pt, err := aed.Open(nil, make([]byte, aed.NonceSize()), aesCT, nil)
	must(err)
	os.Stdout.Write(pt)
}
