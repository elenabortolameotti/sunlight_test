# Sunlight BLS Test Suite

This directory contains self-contained, reproducible test scripts for verifying the BLS (Boneh-Lynn-Shacham) witness signature implementation in Sunlight.

## Quick Start

The tests are **fully self-contained** and create all necessary assets (certificates, configs, databases) automatically. Just run:

```bash
# Build the binaries first
cd /path/to/sunlight
go build -o sunlight-test ./cmd/sunlight/
go build -o bls-verify ./cmd/bls-verify/

# Run the test
./test/bls_test.sh
```


## Comprehensive BLS Test (`bls_test.sh`)

1. **Log Creation** - Creates a log with **3 BLS witnesses** (configurable)
2. **Certificate Submission** - Submits 5 test certificates to the log
3. **Checkpoint Evolution** - Verifies checkpoints as the log grows
4. **BLS Signatures** - Confirms **aggregated** BLS witness signatures
5. **Format Validation** - Validates 96-byte BLS12-381 aggregate signature format
6. **Client Verification** - Tests client-side checkpoint verification

### Multiple Witnesses Support

The test script creates 3 witnesses by default, but you can configure any number.

**Multiple witnesses:**
```yaml
witnesses:
  - name: witness-1
    secret: /path/to/witness1.bin
  - name: witness-2
    secret: /path/to/witness2.bin
  - name: witness-3
    secret: /path/to/witness3.bin
```

All witness signatures are aggregated into a single 96-byte BLS signature. The checkpoint will show:
```
— witness-agg witness-1+hash1,witness-2+hash2,witness-3+hash3 <base64-signature>
```

### What This Test Verifies

**Log Creation with Multiple BLS Witnesses**
- Creates a new log with **3 witness configurations** (default)
- Each witness generates a unique BLS12-381 key pair
- All witness signatures are aggregated into a single signature

**Certificate Submission**
- Submits 5 test certificates via `add-chain` endpoint
- Certificates are validated and sequenced

**BLS Aggregate Signatures on Checkpoints**
- Checkpoints contain `witness-agg` signatures
- **Single 96-byte signature** represents all witnesses (BLS aggregation)
- Each witness identified by `name+hash` in the signature line
- Key hashes are 4-byte truncated SHA-256 per witness

**Client-Side Verification**
- Client can fetch and parse checkpoints
- Client can validate BLS signature format
- Client can verify checkpoint structure

### Requirements

- Built `sunlight-test` binary in repo root
- Built `bls-verify` binary in repo root (optional but recommended)
- OpenSSL for certificate generation
- curl for HTTP testing
- Python3 (for monitoring HTTP server)


### Test Architecture

The test sets up:

1. **Monitoring Server** (port 8444) - Serves checkpoint files
2. **Sunlight Server** (port 8443) - CT log with BLS witness
3. **Test CA** - Issues test certificates
4. **5 Test Certificates** - Submitted to the log

### BLS Implementation Details

- **Curve**: BLS12-381
- **Signature Type**: **Aggregate signatures** on G2
- **Signature Size**: **96 bytes** (compressed, regardless of number of witnesses!)
- **Key Derivation**: From 32-byte seed using HKDF per witness
- **Key Hash**: SHA-256 truncated to 4 bytes (8 hex chars) per witness
- **Format**: `witness-agg <name1+hash1,name2+hash2,...> <base64-aggregate-signature>`
- **Aggregation**: Multiple witness signatures combined into one using BLS properties
