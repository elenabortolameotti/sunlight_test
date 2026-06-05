package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	for _, name := range []string{"RT-1", "RT-2", "RT-3"} {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		fmt.Printf("  %s_seed: %s\n", name, base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Printf("  %s_pub:  %s\n", name, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	}
}
