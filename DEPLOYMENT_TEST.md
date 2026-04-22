# Sunlight Test Deployment Guide

This guide explains how to deploy a test Sunlight Certificate Transparency log server and client to verify that all operations are functioning correctly.

## Overview

Sunlight is a production-ready Static Certificate Transparency log implementation. This guide covers:

1. Setting up a local test server with SQLite and local filesystem storage
2. Configuring the test environment with self-signed certificates
3. Testing all write-path operations (add-chain, add-pre-chain, get-roots)
4. Testing all read-path operations (checkpoint, entries, inclusion proofs)
5. Verifying client-server interactions

## Prerequisites

- Go 1.24 or later
- OpenSSL (for generating test certificates)
- curl or httpie (for manual API testing)

## 1. Build the Tools

```bash
# Install sunlight (the CT log server)
go install filippo.io/sunlight/cmd/sunlight@latest

# Install skylight (the read-path file server)
go install filippo.io/sunlight/cmd/skylight@latest

# Install sunlight-keygen (for generating log keys)
go install filippo.io/sunlight/cmd/sunlight-keygen@latest

# Verify installations
which sunlight
which skylight
which sunlight-keygen
```

## 2. Create Test Directory Structure

```bash
mkdir -p ~/sunlight-test/{logs,data,certs,config}
cd ~/sunlight-test
```

## 3. Generate Test Keys and Certificates

### 3.1 Generate Log Secret

```bash
# Generate a 32-byte seed for the log's private key
sunlight-keygen -f logs/testlog.seed.bin

# Verify the seed file
ls -la logs/testlog.seed.bin  # Should be exactly 32 bytes
```

### 3.2 Create Self-Signed TLS Certificate

Since we're testing locally without ACME:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out certs/sunlight-key.pem -pkeyopt rsa_keygen_bits:2048

# Generate self-signed certificate
openssl req -new -x509 -key certs/sunlight-key.pem -out certs/sunlight.pem -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

### 3.3 Create Test Root CA and Certificate Chain

```bash
# Create test CA key and certificate
openssl genpkey -algorithm RSA -out certs/ca-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key certs/ca-key.pem -out certs/ca-cert.pem -days 365 \
  -subj "/CN=Test CA/O=Sunlight Test/C=US"

# Create a test server key and CSR
openssl genpkey -algorithm RSA -out certs/server-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key certs/server-key.pem -out certs/server.csr \
  -subj "/CN=test.example.com/O=Test/C=US"

# Sign the server certificate with our test CA
openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
  -CAcreateserial -out certs/server-cert.pem -days 30 \
  -extensions v3_req -extfile <(echo "[v3_req]
subjectAltName=DNS:test.example.com")

# Create the certificate chain (server cert + CA cert)
cat certs/server-cert.pem certs/ca-cert.pem > certs/chain.pem
```

### 3.4 Create a Test Precertificate (for add-pre-chain testing)

```bash
# Create a test precertificate signing key
openssl genpkey -algorithm RSA -out certs/preissuer-key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key certs/preissuer-key.pem -out certs/preissuer-cert.pem -days 30 \
  -subj "/CN=Test Preissuer/O=Sunlight Test/C=US" \
  -extensions v3_ca -extfile <(echo "[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")

# Create a precertificate (this is a simplified example)
# In practice, precertificates are created using the CT poison extension
```

## 4. Initialize the Checkpoints Database

The checkpoints database is required for the global lock backend:

```bash
# Create the SQLite database for checkpoints
sqlite3 data/checkpoints.db "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"

# Verify the database was created
ls -la data/checkpoints.db
```

## 5. Create the Sunlight Configuration

Create `~/sunlight-test/config/sunlight.yaml`:

```yaml
listen:
  - ":8443"

checkpoints: /home/USERNAME/sunlight-test/data/checkpoints.db

logs:
  - shortname: testlog2025
    # Use today's date as inception date (YYYYMMDD format)
    inception: "2025-04-22"
    
    # Set the temporal validity window
    notafterstart: "2025-01-01T00:00:00Z"
    notafterlimit: "2026-01-01T00:00:00Z"
    
    # Submission endpoint URL
    submissionprefix: https://localhost:8443/testlog2025
    
    # Monitoring endpoint URL (where tiles will be served from)
    monitoringprefix: https://localhost:8444/testlog2025
    
    # Path to the secret seed
    secret: /home/USERNAME/sunlight-test/logs/testlog.seed.bin
    
    # Sequencing period (milliseconds) and pool size
    period: 1000
    poolsize: 100
    
    # Local storage directory
    localdirectory: /home/USERNAME/sunlight-test/data/testlog2025
    
    # Deduplication cache
    cache: /home/USERNAME/sunlight-test/data/testlog2025-cache.db
    
    # Trusted roots (our test CA)
    roots: /home/USERNAME/sunlight-test/certs/ca-cert.pem
```

**Note:** Replace `USERNAME` with your actual username.

## 6. Start the Sunlight Server

```bash
cd ~/sunlight-test

# Run with test certificates (skips ACME)
sunlight -c config/sunlight.yaml -testcert
```

You should see output indicating:
- The log is being created (on the inception date)
- The checkpoint database is loaded
- The server is listening on port 8443

Keep this terminal running.

## 7. Test the Write-Path Operations

Open a new terminal and run these tests:

### 7.1 Test get-roots

```bash
curl -k https://localhost:8443/testlog2025/ct/v1/get-roots | jq .
```

Expected output: JSON with a `certificates` array containing the base64-encoded root CA certificate.

### 7.2 Test add-chain

```bash
# Submit the certificate chain
curl -k -X POST https://localhost:8443/testlog2025/ct/v1/add-chain \
  -H "Content-Type: application/json" \
  -d @- << 'EOF' | jq .
{
  "chain": [
    "$(base64 -w 0 ~/sunlight-test/certs/server-cert.pem)",
    "$(base64 -w 0 ~/sunlight-test/certs/ca-cert.pem)"
  ]
}
EOF
```

Or more directly:

```bash
# Create the JSON payload
CHAIN_JSON=$(cat <<EOF
{
  "chain": [
    "$(base64 -w 0 ~/sunlight-test/certs/server-cert.pem)",
    "$(base64 -w 0 ~/sunlight-test/certs/ca-cert.pem)"
  ]
}
EOF
)

curl -k -X POST https://localhost:8443/testlog2025/ct/v1/add-chain \
  -H "Content-Type: application/json" \
  -d "$CHAIN_JSON" | jq .
```

Expected output: A signed certificate timestamp (SCT) with:
- `sct_version`: 1
- `timestamp`: The current timestamp
- `id`: The log ID (base64-encoded)
- `extensions`: Leaf index extension
- `signature`: The SCT signature

Save the `signature` and `extensions` fields for later verification.

### 7.3 Test add-pre-chain (if you have a precertificate)

```bash
curl -k -X POST https://localhost:8443/testlog2025/ct/v1/add-pre-chain \
  -H "Content-Type: application/json" \
  -d '{
    "chain": [
      "<base64-precert>",
      "<base64-preissuer>",
      "<base64-ca-cert>"
    ]
  }' | jq .
```

## 8. Start the Read-Path Server (Skylight)

The read-path serves the static tiles. In production, this might be a CDN or object storage.

Create `~/sunlight-test/config/skylight.yaml`:

```yaml
listen:
  - ":8444"

checkpoints: /home/USERNAME/sunlight-test/data/checkpoints.db

logs:
  - shortname: testlog2025
    localdirectory: /home/USERNAME/sunlight-test/data/testlog2025
    submissionprefix: https://localhost:8443/testlog2025
    monitoringprefix: https://localhost:8444/testlog2025
```

Start skylight:

```bash
skylight -c config/skylight.yaml -testcert
```

## 9. Test the Read-Path Operations

### 9.1 Fetch the Checkpoint

```bash
curl -k https://localhost:8444/testlog2025/checkpoint
```

Expected output: A signed note containing:
- Log origin name
- Tree size (number of entries)
- Root hash
- Signatures from the log

### 9.2 Fetch a Data Tile

```bash
# Fetch the first data tile (entries 0-255)
curl -k https://localhost:8444/testlog2025/tile/data/000 | gunzip | xxd | head -20
```

### 9.3 Fetch an Issuer Certificate

```bash
# Calculate the fingerprint of the CA cert
FINGERPRINT=$(openssl x509 -in ~/sunlight-test/certs/ca-cert.pem -outform DER | sha256sum | cut -d' ' -f1)

# Fetch the issuer
curl -k https://localhost:8444/testlog2025/issuer/$FINGERPRINT | openssl x509 -inform DER -text
```

## 10. Test with the Go Client

Create a test client program `~/sunlight-test/testclient.go`:

```go
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"filippo.io/sunlight"
)

func main() {
	// Read the log's public key
	// In a real scenario, you'd get this from a trusted source
	keyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... (get this from log setup output)
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		log.Fatal("failed to parse PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse public key:", err)
	}

	// Create client
	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://localhost:8444/testlog2025",
		PublicKey:        pubKey,
		UserAgent:        "TestClient (test@example.com)",
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	})
	if err != nil {
		log.Fatal("failed to create client:", err)
	}

	// Test 1: Fetch and verify checkpoint
	fmt.Println("=== Test 1: Checkpoint ===")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	checkpoint, note, err := client.Checkpoint(ctx)
	if err != nil {
		log.Fatal("failed to get checkpoint:", err)
	}
	fmt.Printf("Tree size: %d\n", checkpoint.Tree.N)
	fmt.Printf("Root hash: %x\n", checkpoint.Tree.Hash)
	fmt.Printf("Signatures: %d\n", len(note.Sigs))

	// Test 2: Fetch entries
	fmt.Println("\n=== Test 2: Entries ===")
	if checkpoint.Tree.N > 0 {
		for i, entry := range client.Entries(ctx, checkpoint.Tree, 0) {
			fmt.Printf("Entry %d: index=%d, timestamp=%d\n", i, entry.LeafIndex, entry.Timestamp)
			if i >= 5 {
				break // Just show first 5
			}
		}
		if err := client.Err(); err != nil {
			log.Fatal("error iterating entries:", err)
		}
	}

	// Test 3: Fetch specific entry
	fmt.Println("\n=== Test 3: Specific Entry ===")
	if checkpoint.Tree.N > 0 {
		entry, proof, err := client.Entry(ctx, checkpoint.Tree, 0)
		if err != nil {
			log.Fatal("failed to get entry:", err)
		}
		fmt.Printf("Entry 0: index=%d, timestamp=%d\n", entry.LeafIndex, entry.Timestamp)
		fmt.Printf("Proof length: %d\n", len(proof))
	}

	// Test 4: Unauthenticated trimmed entries (names only)
	fmt.Println("\n=== Test 4: UnauthenticatedTrimmedEntries ===")
	for i, entry := range client.UnauthenticatedTrimmedEntries(ctx, 0, checkpoint.Tree.N) {
		fmt.Printf("Entry %d: timestamp=%d, DNS=%v\n", i, entry.Timestamp, entry.DNS)
		if i >= 5 {
			break
		}
	}
	if err := client.Err(); err != nil {
		log.Fatal("error iterating trimmed entries:", err)
	}

	fmt.Println("\n=== All tests passed! ===")
}
```

Run the client:

```bash
cd ~/sunlight-test
go run testclient.go
```

## 11. Automated Testing Script

Create a comprehensive test script `~/sunlight-test/run-tests.sh`:

```bash
#!/bin/bash

set -e

BASE_URL="https://localhost:8443/testlog2025"
READ_URL="https://localhost:8444/testlog2025"

echo "=== Sunlight Test Suite ==="
echo

# Test 1: Health check
echo "Test 1: Health check"
curl -k -s -o /dev/null -w "%{http_code}" "$BASE_URL/ct/v1/get-roots" | grep -q "200" && echo "PASS" || echo "FAIL"
echo

# Test 2: Get roots
echo "Test 2: Get roots"
curl -k -s "$BASE_URL/ct/v1/get-roots" | jq -e '.certificates | length > 0' > /dev/null && echo "PASS" || echo "FAIL"
echo

# Test 3: Add certificate chain
echo "Test 3: Add certificate chain"
CHAIN_JSON=$(cat <<EOF
{
  "chain": [
    "$(base64 -w 0 ~/sunlight-test/certs/server-cert.pem)",
    "$(base64 -w 0 ~/sunlight-test/certs/ca-cert.pem)"
  ]
}
EOF
)
RESPONSE=$(curl -k -s -X POST "$BASE_URL/ct/v1/add-chain" \
  -H "Content-Type: application/json" \
  -d "$CHAIN_JSON")
echo "$RESPONSE" | jq -e '.sct_version == 1' > /dev/null && echo "PASS" || echo "FAIL"
echo

# Test 4: Get checkpoint (read path)
echo "Test 4: Get checkpoint"
sleep 2  # Wait for sequencing
curl -k -s "$READ_URL/checkpoint" | grep -q "testlog2025" && echo "PASS" || echo "FAIL"
echo

# Test 5: Fetch data tile
echo "Test 5: Fetch data tile"
curl -k -s "$READ_URL/tile/data/000" | gunzip > /dev/null 2>&1 && echo "PASS" || echo "FAIL"
echo

# Test 6: Fetch issuer
echo "Test 6: Fetch issuer"
FINGERPRINT=$(openssl x509 -in ~/sunlight-test/certs/ca-cert.pem -outform DER | sha256sum | cut -d' ' -f1)
curl -k -s -o /dev/null -w "%{http_code}" "$READ_URL/issuer/$FINGERPRINT" | grep -q "200" && echo "PASS" || echo "FAIL"
echo

# Test 7: Verify log metadata
echo "Test 7: Log metadata"
curl -k -s "$BASE_URL/log.v3.json" | jq -e '.log_id' > /dev/null && echo "PASS" || echo "FAIL"
echo

echo "=== Test Suite Complete ==="
```

Make it executable and run:

```bash
chmod +x ~/sunlight-test/run-tests.sh
~/sunlight-test/run-tests.sh
```

## 12. Expected Operations Summary

### Write-Path Operations (Sunlight Server)

| Operation | Endpoint | Description |
|-----------|----------|-------------|
| `add-chain` | `POST /ct/v1/add-chain` | Submit a certificate chain |
| `add-pre-chain` | `POST /ct/v1/add-pre-chain` | Submit a precertificate chain |
| `get-roots` | `GET /ct/v1/get-roots` | Get accepted root certificates |

### Read-Path Operations (Skylight / Static Files)

| Operation | Endpoint | Description |
|-----------|----------|-------------|
| Checkpoint | `GET /checkpoint` | Get signed tree head |
| Data tiles | `GET /tile/data/{path}` | Get certificate entries |
| Hash tiles | `GET /tile/{level}/{path}` | Get Merkle tree tiles |
| Names tiles | `GET /tile/names/{path}` | Get trimmed name entries |
| Issuers | `GET /issuer/{fingerprint}` | Get issuer certificates |
| Metadata | `GET /log.v3.json` | Get log metadata |

### Client Operations (Go Library)

| Method | Description |
|--------|-------------|
| `Checkpoint()` | Fetch and verify signed tree head |
| `Entries()` | Iterate over log entries with authentication |
| `Entry()` | Fetch specific entry with inclusion proof |
| `CheckInclusion()` | Verify an SCT is included in the log |
| `Issuer()` | Fetch issuer certificate by fingerprint |
| `UnauthenticatedTrimmedEntries()` | Get name feed (no authentication) |

## 13. Troubleshooting

### Issue: "checkpoints database does not exist"
**Solution:** Make sure you created the checkpoints database with the correct schema (Step 4).

### Issue: "log not found, but today is not the Inception date"
**Solution:** The inception date in the config must match today's date. Update the config or wait until the specified date.

### Issue: "checkpoints from Backend and MonitoringPrefix don't match"
**Solution:** On first run, the monitoring prefix might not have a checkpoint yet. This is normal.

### Issue: "certificate verification failed"
**Solution:** Ensure your test certificate:
- Has a valid chain to a trusted root
- Has a NotAfter date within the log's configured window
- Has the required extensions for server auth

### Issue: Client "InsecureSkipVerify" warning
**Solution:** In production, use proper certificates. For testing, the client code above shows how to skip verification.

## 14. Cleanup

```bash
# Stop the servers (Ctrl+C in their terminals)

# Remove test data
rm -rf ~/sunlight-test

# Remove installed binaries (optional)
go clean -i filippo.io/sunlight/cmd/...
```

## 15. Next Steps

For production deployment:

1. Use proper ACME certificates (Let's Encrypt)
2. Set up S3-compatible storage instead of local filesystem
3. Configure multiple logs for temporal sharding
4. Set up monitoring with Prometheus
5. Use DynamoDB or SQLite for the checkpoints backend
6. Configure a CDN for the read-path

See the [README.md](README.md) for production configuration details.
