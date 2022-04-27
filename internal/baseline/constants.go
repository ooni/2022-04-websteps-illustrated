package baseline

//
// Contains constants used by the baseline experiment.
//

import (
	_ "embed"
	"io/fs"
	"os"
)

// defaultIPv4Addr is the returned IPv4 address.
const defaultIPv4Addr = "142.93.237.101"

// defaultWebpage is the returned webpage.
//go:embed "index.html"
var defaultWebpage []byte

// defaultTLSCert is the default TLS cert.
//go:embed "cert.pem"
var defaultTLSCert []byte

// defaultTLSKey is the default TLS key.
//go:embed "key.pem"
var defaultTLSKey []byte

// WriteTLSCert writes the cert to disk.
func WriteTLSCert(filename string, perms fs.FileMode) error {
	return os.WriteFile(filename, defaultTLSCert, perms)
}

// WriteTLSKey writes the key to disk.
func WriteTLSKey(filename string, perms fs.FileMode) error {
	return os.WriteFile(filename, defaultTLSKey, perms)
}
