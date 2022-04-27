// Command baselined is the baseline test helper server.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bassosimone/getoptx"
	"github.com/bassosimone/websteps-illustrated/internal/baseline"
	"github.com/bassosimone/websteps-illustrated/internal/privileges"
)

// CLI is the command line interface.
type CLI struct {
	Address string `doc:"IPv4 or IPv6 address where to listen" short:"A"`
	Datadir string `doc:"directory where to write data (e.g., TLS certs)"`
	Help    bool   `doc:"prints this help message" short:"h"`
	User    string `doc:"user to drop privileges to (Linux only; default: nobody)" short:"u"`
}

// getopt parses command line options.
func getopt() *CLI {
	opts := &CLI{
		Address: "127.0.0.1",
		Datadir: ".",
		Help:    false,
		User:    "nobody",
	}
	parser := getoptx.MustNewParser(opts, getoptx.NoPositionalArguments())
	parser.MustGetopt(os.Args)
	if opts.Help {
		parser.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	return opts
}

// tlsfiles returns the name of TLS files.
func tlsfiles(opts *CLI) (certfile string, keyfile string) {
	certfile = filepath.Join(opts.Datadir, "cert.pem")
	keyfile = filepath.Join(opts.Datadir, "key.pem")
	return
}

// writetlsfiles writes TLS files on disk.
func writetlsfiles(certfile, keyfile string) error {
	if err := baseline.WriteTLSCert(certfile, 0644); err != nil {
		return err
	}
	if err := baseline.WriteTLSKey(keyfile, 0644); err != nil {
		return err
	}
	return nil
}

func main() {
	opts := getopt()
	certfile, keyfile := tlsfiles(opts)
	if err := writetlsfiles(certfile, keyfile); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s\n", err.Error())
		os.Exit(1)
	}
	srvr := baseline.NewServer(certfile, keyfile)
	listener, err := srvr.Listen(opts.Address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s\n", err.Error())
		os.Exit(1)
	}
	privileges.Drop(opts.User)
	listener.Start()
	<-context.Background().Done() // block forever
}
