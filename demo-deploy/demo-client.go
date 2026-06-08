package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Demo entity private key seeds (32 bytes each)
var entitySeeds = map[string]string{
	"PM-1": "Hh+zhFHKlq9RLmDvDYhr3EMPK06E1ljj0+BJSJe/7aY=",
	"RT-1": "Hh+zhFHKlq9RLmDvDYhr3EMPK06E1ljj0+BJSJe/7aY=",
	"RT-2": "xnGlti97k5BYO8rzVmHhscjDJymLnaQDPeqtRVXAyuI=",
	"RT-3": "ydqRXrOvAtHQBDbyP4DU7MGVJGh5831E49X3/LywaQ0=",
}

func getPrivKey(entityID string) ed25519.PrivateKey {
	seed, _ := base64.StdEncoding.DecodeString(entitySeeds[entityID])
	return ed25519.NewKeyFromSeed(seed)
}

func signEntry(wbbData, entityID string) map[string]interface{} {
	priv := getPrivKey(entityID)
	ts := time.Now().UnixMilli()

	var buf bytes.Buffer
	buf.WriteString(wbbData)
	buf.WriteString(entityID)
	buf.WriteString(fmt.Sprintf("%d", ts))
	msg := sha256.Sum256(buf.Bytes())
	sig := ed25519.Sign(priv, msg[:])

	return map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString([]byte(wbbData)),
		"entity_id": entityID,
		"timestamp": ts,
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
}

func post(baseURL string, body map[string]interface{}) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/submit", "application/json", bytes.NewReader(b))
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var pretty map[string]interface{}
	json.Unmarshal(respBody, &pretty)
	prettyJSON, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Printf("Status: %d\n%s\n", resp.StatusCode, prettyJSON)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: demo-client <baseURL> <command>")
		fmt.Println("  demo-client http://localhost:8080/ctlog demo")
		os.Exit(1)
	}

	baseURL := os.Args[1]
	cmd := os.Args[2]

	if cmd != "demo" {
		fmt.Println("Unknown command:", cmd)
		os.Exit(1)
	}

	fmt.Println("=== Sunlight Staging + Phase Manager Demo ===\n")
	fmt.Println("Board:", baseURL)
	fmt.Println()

	// === SETUP PHASE ===
	fmt.Println("=== SETUP PHASE ===\n")

	wbb := "setup,RT,acc_pub_key,2,pk_data"

	fmt.Println("→ Step 1: RT-1 submits")
	post(baseURL, signEntry(wbb, "RT-1"))
	fmt.Println()

	fmt.Println("→ Step 2: RT-2 submits (threshold met, grace period)")
	post(baseURL, signEntry(wbb, "RT-2"))
	fmt.Println()

	fmt.Println("→ Step 3: RT-3 submits (all signers present → early publication)")
	post(baseURL, signEntry(wbb, "RT-3"))
	fmt.Println()

	fmt.Println("→ Step 4: Waiting 11s for grace period...")
	time.Sleep(11 * time.Second)

	fmt.Println("→ Step 5: RT-1 duplicate (should be rejected)")
	post(baseURL, signEntry(wbb, "RT-1"))
	fmt.Println()

	// === PHASE TRANSITION: setup → voting ===
	fmt.Println("=== PHASE TRANSITION: setup → voting ===\n")

	fmt.Println("→ Step 6: PM-1 submits phase_transition entry (logged as leaf 1)")
	post(baseURL, signEntry("setup,PM,phase_transition,1,voting", "PM-1"))
	fmt.Println()

	// === VOTING PHASE ===
	fmt.Println("=== VOTING PHASE ===\n")

	fmt.Println("→ Step 7: RT-1 submits setup entry (should be rejected - wrong phase)")
	post(baseURL, signEntry("setup,RT,acc_pub_key,2,pk_data2", "RT-1"))
	fmt.Println()

	// === PHASE TRANSITION: voting → tallying ===
	fmt.Println("=== PHASE TRANSITION: voting → tallying ===\n")

	fmt.Println("→ Step 8: PM-1 submits phase_transition entry (logged as leaf 2)")
	post(baseURL, signEntry("voting,PM,phase_transition,1,tallying", "PM-1"))
	fmt.Println()

	// === TALLYING PHASE ===
	fmt.Println("=== TALLYING PHASE ===\n")

	fmt.Println("→ Step 9: RT-1 submits setup entry (should be rejected - wrong phase)")
	post(baseURL, signEntry("setup,RT,acc_pub_key,2,pk_data3", "RT-1"))
	fmt.Println()

	// === INVALID PHASE TRANSITION ===
	fmt.Println("=== INVALID PHASE TRANSITION ===\n")

	fmt.Println("→ Step 10: PM-1 submits invalid backwards transition (tallying → setup)")
	post(baseURL, signEntry("tallying,PM,phase_transition,1,setup", "PM-1"))
	fmt.Println()

	fmt.Println("=== Demo Complete ===")
}
