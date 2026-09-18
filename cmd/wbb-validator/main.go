// Command wbb-validator is an independent validator of the referendum WBB
// (fork patch P6): it rebuilds the log's Merkle tree from the published
// leaves, checks it against the signed checkpoint, and BLS-signs every leaf
// it has verified, submitting the signature to the log.
//
// Usage:
//
//	wbb-validator -name V-1 -seed-file validator-1-seed.bin -print-key
//	wbb-validator -name V-1 -seed-file validator-1-seed.bin \
//	    -log https://127.0.0.1:8090/wbb -cacert ca.pem -delay 3s
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"filippo.io/sunlight/internal/my_crypto"
	"filippo.io/sunlight/internal/validation"
)

func main() {
	fs := flag.NewFlagSet("wbb-validator", flag.ExitOnError)
	name := fs.String("name", "", "validator id (as registered in the log's validator_bls_keys)")
	seedFile := fs.String("seed-file", "", "path to the 32-byte BLS key seed")
	logURL := fs.String("log", "https://127.0.0.1:8090/wbb", "log submission prefix")
	caCert := fs.String("cacert", "", "PEM CA certificate to trust for the log's TLS (default: system roots)")
	interval := fs.Duration("interval", time.Second, "how often to look for new leaves")
	delay := fs.Duration("delay", 3*time.Second, "deliberate pause before signing each leaf")
	printKey := fs.Bool("print-key", false, "print the base64 BLS public key and exit")
	fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fatal := func(msg string, args ...any) {
		logger.Error(msg, args...)
		os.Exit(1)
	}

	if *name == "" || *seedFile == "" {
		fatal("-name and -seed-file are required")
	}
	seed, err := os.ReadFile(*seedFile)
	if err != nil {
		fatal("read seed file", "err", err)
	}
	signer, err := my_crypto.NewBLSSignerFromSeed(*name, 0, seed)
	if err != nil {
		fatal("derive BLS key", "err", err)
	}
	if *printKey {
		pk, err := signer.PublicKeyBytes()
		if err != nil {
			fatal("public key", "err", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pk))
		return
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *caCert != "" {
		pem, err := os.ReadFile(*caCert)
		if err != nil {
			fatal("read CA certificate", "err", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fatal("no certificate found in CA file", "path", *caCert)
		}
		tlsConfig.RootCAs = pool
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	validator, err := validation.New(validation.Config{
		Name:       *name,
		Signer:     signer,
		LogURL:     *logURL,
		HTTPClient: client,
		Delay:      *delay,
		Logger:     logger,
	})
	if err != nil {
		fatal("configure validator", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	logger.Info("validator started", "validator", *name, "log", *logURL,
		"interval", interval.String(), "delay", delay.String())
	if err := validator.Run(ctx, *interval); err != nil && ctx.Err() == nil {
		fatal("validator stopped", "err", err)
	}
}
