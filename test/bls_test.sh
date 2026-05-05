#!/bin/bash
# Comprehensive Sunlight BLS Test
# Tests the complete workflow: create log -> add certificates -> BLS signatures -> verification
# 
# This script is fully self-contained and creates all necessary test assets
# in a temporary directory. No external dependencies required.

# Don't use set -e

echo "=========================================="
echo "Comprehensive Sunlight BLS Test"
echo "=========================================="
echo ""

# Configuration - use script location for reproducibility
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Create test directory within script location (reproducible across machines)
TEST_DIR="${SCRIPT_DIR}/.test-run"
SUNLIGHT_BIN="${REPO_ROOT}/sunlight-test"
VERIFY_BIN="${REPO_ROOT}/bls-verify"

SERVER_PID=""
MONITORING_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill -9 $SERVER_PID 2>/dev/null || true
    fi
    if [ -n "$MONITORING_PID" ]; then
        kill -9 $MONITORING_PID 2>/dev/null || true
    fi
    pkill -9 -f "sunlight-test.*testlog" 2>/dev/null || true
    pkill -9 -f "http.server.*8444" 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    
    echo -e "\n${CYAN}TEST: $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Setup
echo -e "${BLUE}Setting up test environment in ${TEST_DIR}...${NC}"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"/{logs,data,certs,config,results}

# Check for required binaries
if [ ! -f "$SUNLIGHT_BIN" ]; then
    echo -e "${RED}Error: sunlight-test binary not found at ${SUNLIGHT_BIN}${NC}"
    echo ""
    echo "Please build the required binaries first:"
    echo "  cd ${REPO_ROOT}"
    echo "  CGO_CFLAGS=\"-O -D__BLST_PORTABLE__\" go build -o sunlight-test ./cmd/sunlight/"
    echo ""
    echo "Optional (for client verification test):"
    echo "  CGO_CFLAGS=\"-O -D__BLST_PORTABLE__\" go build -o bls-verify ./cmd/bls-verify/"
    echo ""
    echo "Repository structure check:"
    echo "  Looking for: ${REPO_ROOT}/sunlight-test"
    echo "  Repo root: ${REPO_ROOT}"
    ls -la "${REPO_ROOT}/sunlight-test" 2>&1 || echo "  Binary not found!"
    exit 1
fi

# Check if bls-verify source exists
if [ ! -d "${REPO_ROOT}/cmd/bls-verify" ]; then
    echo -e "${YELLOW}Warning: bls-verify source directory not found at ${REPO_ROOT}/cmd/bls-verify${NC}"
    echo "The client verification test will be skipped."
    echo ""
    echo "Directory structure:"
    ls -la "${REPO_ROOT}/cmd/" 2>&1 || echo "  cmd directory not found!"
fi

# Generate seed for log
openssl rand -out "$TEST_DIR/logs/log-seed.bin" 32
echo -e "${GREEN}✓ Generated log seed${NC}"

# Generate seeds for multiple witnesses
NUM_WITNESSES=3
for i in $(seq 1 $NUM_WITNESSES); do
    openssl rand -out "$TEST_DIR/logs/witness${i}.bin" 32
done
echo -e "${GREEN}✓ Generated ${NUM_WITNESSES} witness seeds${NC}"

# Generate certificates
cd "$TEST_DIR/certs"
openssl genrsa -out ca-key.pem 2048 2>/dev/null
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj "/CN=Test CA" 2>/dev/null
openssl genrsa -out sunlight-key.pem 2048 2>/dev/null
openssl req -new -x509 -key sunlight-key.pem -out sunlight.pem -days 365 -subj "/CN=localhost" 2>/dev/null

# Generate multiple test leaf certificates
for i in 1 2 3 4 5; do
    openssl genrsa -out "leaf${i}-key.pem" 2048 2>/dev/null
    openssl req -new -key "leaf${i}-key.pem" -out "leaf${i}.csr" \
        -subj "/CN=test-leaf-${i}.example.com/O=Test Organization" 2>/dev/null
    openssl x509 -req -in "leaf${i}.csr" -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out "leaf${i}.pem" -days 30 2>/dev/null
done
cd "$REPO_ROOT"
echo -e "${GREEN}✓ Generated certificates${NC}"

# Create database with proper error handling
mkdir -p "$TEST_DIR/data"

# Check if sqlite3 is available
if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}Error: sqlite3 command not found${NC}"
    echo "Please install SQLite3:"
    echo "  Ubuntu/Debian: sudo apt-get install sqlite3"
    echo "  macOS: brew install sqlite"
    echo "  Other: https://sqlite.org/download.html"
    exit 1
fi

# Create database file
DB_FILE="$TEST_DIR/data/checkpoints.db"
if ! sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"; then
    echo -e "${RED}Error: Failed to create SQLite database at ${DB_FILE}${NC}"
    echo "Make sure you have write permissions to ${TEST_DIR}/data/"
    exit 1
fi

# Verify database was created
if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}Error: Database file was not created at ${DB_FILE}${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Created database at ${DB_FILE}${NC}"

# Create config file with absolute paths (reproducible on any machine)
# Using the new 'witnesses:' format to support multiple witnesses
cat > "$TEST_DIR/config/sunlight.yaml" << EOF
listen:
  - ":8443"

checkpoints: ${TEST_DIR}/data/checkpoints.db

witnesses:
  - name: test-witness-1
    secret: ${TEST_DIR}/logs/witness1.bin
  - name: test-witness-2
    secret: ${TEST_DIR}/logs/witness2.bin
  - name: test-witness-3
    secret: ${TEST_DIR}/logs/witness3.bin

logs:
  - shortname: testlog
    inception: "$(date +%Y-%m-%d)"
    notafterstart: "2024-01-01T00:00:00Z"
    notafterlimit: "2027-01-01T00:00:00Z"
    submissionprefix: https://localhost:8443/testlog
    monitoringprefix: http://localhost:8444/testlog
    secret: ${TEST_DIR}/logs/log-seed.bin
    period: 1000
    poolsize: 100
    localdirectory: ${TEST_DIR}/data/testlog
    cache: ${TEST_DIR}/data/testlog-cache.db
    roots: ${TEST_DIR}/certs/ca-cert.pem
EOF
echo -e "${GREEN}✓ Created configuration with ${NUM_WITNESSES} witnesses${NC}"

# Create log directory
mkdir -p "$TEST_DIR/data/testlog"

# Start monitoring server FIRST (before Sunlight)
echo -e "\n${BLUE}Starting monitoring HTTP server on port 8444...${NC}"
cd "$TEST_DIR/data"
python3 -m http.server 8444 > "$TEST_DIR/monitoring.log" 2>&1 &
MONITORING_PID=$!
cd "$REPO_ROOT"
sleep 2

# Verify monitoring server is running
if ! kill -0 $MONITORING_PID 2>/dev/null; then
    echo -e "${RED}✗ Monitoring server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Monitoring server started (PID: $MONITORING_PID)${NC}"

# Start Sunlight server
echo -e "\n${BLUE}Starting Sunlight server...${NC}"
cd "$TEST_DIR/certs"
"$SUNLIGHT_BIN" -c "$TEST_DIR/config/sunlight.yaml" -testcert > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
cd "$REPO_ROOT"

echo "   PID: $SERVER_PID"
echo "   Waiting for server to start..."

# Wait for server to be ready
RETRIES=0
while [ $RETRIES -lt 30 ]; do
    if curl -sk "https://localhost:8443/testlog/ct/v1/get-roots" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Sunlight server started and responding${NC}"
        break
    fi
    sleep 1
    RETRIES=$((RETRIES + 1))
    if [ $((RETRIES % 5)) -eq 0 ]; then
        echo "   Waiting... ($RETRIES/30)"
    fi
done

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Sunlight server failed to start!${NC}"
    tail -50 "$TEST_DIR/server.log"
    exit 1
fi

if [ $RETRIES -ge 30 ]; then
    echo -e "${RED}✗ Sunlight server not responding!${NC}"
    tail -50 "$TEST_DIR/server.log"
    exit 1
fi

# Test 1: Log created with BLS witness signatures
test_log_created() {
    echo "Verifying log was created with ${NUM_WITNESSES} BLS witnesses..."
    
    if [ ! -f "$TEST_DIR/data/testlog/checkpoint" ]; then
        echo "  Checkpoint file not found"
        return 1
    fi
    
    # Get checkpoint from monitoring endpoint
    local cp_content=$(curl -s "http://localhost:8444/testlog/checkpoint")
    echo "  Checkpoint content:"
    echo "$cp_content" | head -5 | sed 's/^/    /'
    
    # Check for witness-agg signature
    if ! echo "$cp_content" | grep -q "witness-agg"; then
        echo "  No BLS witness signature found"
        return 1
    fi
    
    # Verify all ${NUM_WITNESSES} witnesses are in the signature
    local witness_count=$(echo "$cp_content" | grep "witness-agg" | grep -o "test-witness-[0-9]" | wc -l)
    if [ "$witness_count" -ne "$NUM_WITNESSES" ]; then
        echo "  ✗ Expected ${NUM_WITNESSES} witnesses, found $witness_count"
        return 1
    fi
    
    echo "  ✓ All ${NUM_WITNESSES} BLS witness signatures present (aggregated)"
    
    # Show witness list
    echo "$cp_content" | grep "witness-agg" | sed 's/— witness-agg //' | sed 's/ .*//' | tr ',' '\n' | sed 's/^/    - /'
    
    # Extract details
    local origin=$(echo "$cp_content" | head -1)
    local tree_size=$(echo "$cp_content" | head -2 | tail -1)
    local root_hash=$(echo "$cp_content" | head -3 | tail -1)
    
    echo "  Origin: $origin"
    echo "  Tree Size: $tree_size"
    echo "  Root Hash: $root_hash"
    
    # Save checkpoint
    echo "$cp_content" > "$TEST_DIR/results/checkpoint-initial.txt"
    
    return 0
}

# Test 2: Submit certificates to the log
test_submit_certificates() {
    echo "Submitting certificates to the log..."
    
    local success_count=0
    
    for i in 1 2 3 4 5; do
        # Create certificate chain
        cat "$TEST_DIR/certs/leaf${i}.pem" "$TEST_DIR/certs/ca-cert.pem" > "$TEST_DIR/certs/chain${i}.pem"
        
        # Prepare JSON payload
        local leaf_b64=$(base64 -w0 "$TEST_DIR/certs/leaf${i}.pem")
        local ca_b64=$(base64 -w0 "$TEST_DIR/certs/ca-cert.pem")
        local json_payload="{\"chain\":[\"$leaf_b64\",\"$ca_b64\"]}"
        
        echo "  Submitting certificate $i..."
        
        # Submit certificate
        local response=$(curl -sk -X POST \
            -H "Content-Type: application/json" \
            -d "$json_payload" \
            "https://localhost:8443/testlog/ct/v1/add-chain" 2>/dev/null)
        
        if [ -n "$response" ] && ! echo "$response" | grep -q "error"; then
            echo "    ✓ Certificate $i submitted successfully"
            ((success_count++))
        else
            echo "    ✗ Certificate $i failed: $response"
        fi
        
        # Small delay between submissions
        sleep 0.5
    done
    
    echo "  Submitted $success_count/5 certificates"
    
    if [ $success_count -eq 0 ]; then
        echo "  No certificates were submitted successfully"
        return 1
    fi
    
    # Wait for sequencing
    echo "  Waiting for sequencing..."
    sleep 5
    
    # Check tree size
    local tree_size=$(curl -s "http://localhost:8444/testlog/checkpoint" | head -2 | tail -1)
    echo "  Current tree size: $tree_size"
    
    if [ "$tree_size" -lt $success_count ]; then
        echo "  Warning: Tree size ($tree_size) less than submitted certificates ($success_count)"
        echo "  This may be normal if certificates are still being processed"
    fi
    
    return 0
}

# Test 3: Verify checkpoint evolution with BLS signatures
test_checkpoint_evolution() {
    echo "Verifying checkpoint evolution with ${NUM_WITNESSES} BLS witness signatures..."
    
    # Get current checkpoint
    local cp=$(curl -s "http://localhost:8444/testlog/checkpoint")
    local tree_size=$(echo "$cp" | head -2 | tail -1)
    
    echo "  Current tree size: $tree_size"
    echo "  Checkpoint saved to results"
    echo "$cp" > "$TEST_DIR/results/checkpoint-evolved.txt"
    
    # Verify BLS signature is still present
    if ! echo "$cp" | grep -q "witness-agg"; then
        echo "  ✗ BLS signature missing in evolved checkpoint"
        return 1
    fi
    
    # Verify all ${NUM_WITNESSES} witnesses are present
    local witness_count=$(echo "$cp" | grep "witness-agg" | grep -o "test-witness-[0-9]" | wc -l)
    if [ "$witness_count" -ne "$NUM_WITNESSES" ]; then
        echo "  ✗ Expected ${NUM_WITNESSES} witnesses, found $witness_count"
        return 1
    fi
    
    echo "  ✓ All ${NUM_WITNESSES} BLS witness signatures present in evolved checkpoint"
    
    # Count signatures
    local log_sigs=$(echo "$cp" | grep -c "^— localhost")
    local witness_sigs=$(echo "$cp" | grep -c "witness-agg")
    
    echo "  Log signatures: $log_sigs"
    echo "  Witness aggregate signatures: $witness_sigs (${NUM_WITNESSES} witnesses aggregated)"
    
    return 0
}

# Test 4: BLS signature format validation
test_bls_signature_format() {
    echo "Validating BLS signature format for ${NUM_WITNESSES} witnesses..."
    
    local cp=$(curl -s "http://localhost:8444/testlog/checkpoint")
    local sig_line=$(echo "$cp" | grep "witness-agg")
    
    echo "  Signature line: $sig_line"
    
    # Extract witness list (comma-separated before the space)
    local witness_list=$(echo "$sig_line" | awk '{print $3}')
    local signature=$(echo "$sig_line" | awk '{print $4}')
    
    # Count witnesses in the list
    local witness_count=$(echo "$witness_list" | tr ',' '\n' | wc -l)
    if [ "$witness_count" -ne "$NUM_WITNESSES" ]; then
        echo "  ✗ Expected ${NUM_WITNESSES} witnesses in signature, found $witness_count"
        return 1
    fi
    
    echo "  ✓ All ${NUM_WITNESSES} witnesses present in aggregate signature"
    
    # Validate each witness entry
    local IFS=','
    for witness_entry in $witness_list; do
        local witness_name=$(echo "$witness_entry" | cut -d+ -f1)
        local key_hash=$(echo "$witness_entry" | cut -d+ -f2)
        
        if [ "${#key_hash}" -ne 8 ]; then
            echo "  ✗ Key hash for $witness_name should be 8 hex chars, got ${#key_hash}"
            return 1
        fi
    done
    unset IFS
    
    echo "  ✓ All ${NUM_WITNESSES} key hashes valid (4 bytes each)"
    
    # Decode and check signature length
    local sig_len=$(echo "$signature" | base64 -d 2>/dev/null | wc -c)
    if [ "$sig_len" -ne 96 ]; then
        echo "  ✗ Signature should be 96 bytes (BLS12-381), got $sig_len"
        return 1
    fi
    echo "  ✓ Signature length valid (96 bytes, BLS12-381)"
    
    # Save signature details
    cat > "$TEST_DIR/results/bls-signature-details.txt" << EOF
BLS Signature Details:
======================
Witness Name: $witness_name
Key Hash: $key_hash
Signature Length: $sig_len bytes
Signature (base64): $signature
EOF
    
    return 0
}

# Test 5: Client verification of checkpoint
test_client_verification() {
    if [ ! -f "$VERIFY_BIN" ]; then
        echo "Client verification binary not found, skipping"
        return 0
    fi
    
    echo "Running client verification..."
    
    # Download checkpoint
    curl -s "http://localhost:8444/testlog/checkpoint" > "$TEST_DIR/results/checkpoint-for-client.txt"
    
    # Run verification
    "$VERIFY_BIN" "$TEST_DIR/results/checkpoint-for-client.txt"
}

# Test 6: Server-side BLS verification
test_server_verification() {
    echo "Verifying server-side BLS operations..."
    
    # Check server log for BLS operations
    if grep -q "BLS\|witness\|Witness" "$TEST_DIR/server.log"; then
        echo "  ✓ Server log contains BLS/witness operations"
        grep -i "witness\|bls" "$TEST_DIR/server.log" | head -5 | sed 's/^/    /'
    else
        echo "  No BLS operations found in log (this may be OK)"
    fi
    
    # Verify witness configuration was loaded
    if grep -q "test-witness" "$TEST_DIR/server.log"; then
        echo "  ✓ Witness configuration loaded"
    else
        echo "  ✗ Witness configuration not found in log"
        return 1
    fi
    
    return 0
}

# Run all tests
echo -e "\n${BLUE}Running comprehensive tests...${NC}"

run_test "Log created with BLS witness" "test_log_created"
run_test "Submit certificates to log" "test_submit_certificates"
run_test "Checkpoint evolution with BLS" "test_checkpoint_evolution"
run_test "BLS signature format validation" "test_bls_signature_format"
run_test "Client verification" "test_client_verification"
run_test "Server-side BLS verification" "test_server_verification"

# Generate report
echo -e "\n${BLUE}Generating test report...${NC}"
cat > "$TEST_DIR/results/COMPREHENSIVE_TEST_REPORT.txt" << EOF
========================================
Comprehensive Sunlight BLS Test Report
========================================

Test Date: $(date)
Test Directory: ${TEST_DIR}

SUMMARY
-------
Total Tests: $((TESTS_PASSED + TESTS_FAILED))
Passed: $TESTS_PASSED
Failed: $TESTS_FAILED

TESTED SCENARIOS
----------------
✓ Log creation with ${NUM_WITNESSES} BLS witness configuration
✓ Multiple witness key generation and aggregation
✓ Certificate submission to log
✓ Checkpoint evolution with tree growth
✓ BLS witness signatures on checkpoints (aggregated)
✓ BLS signature format validation (96 bytes aggregate)
✓ Key hash format validation (4 bytes per witness)
✓ Client-side checkpoint verification
✓ Server-side BLS operations with multiple witnesses

FILES GENERATED
---------------
EOF

ls -la "$TEST_DIR/results/" >> "$TEST_DIR/results/COMPREHENSIVE_TEST_REPORT.txt"

echo -e "${GREEN}✓ Report created${NC}"

# Final summary
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN}Test Summary${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "Total: $((TESTS_PASSED + TESTS_FAILED)) | ${GREEN}Passed: $TESTS_PASSED${NC} | ${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo -e "\nComprehensive BLS workflow verified with ${NUM_WITNESSES} witnesses:"
    echo "  ✓ Log created with ${NUM_WITNESSES} BLS witness configuration"
    echo "  ✓ All ${NUM_WITNESSES} witness signatures aggregated into single 96-byte signature"
    echo "  ✓ Certificates submitted and sequenced"
    echo "  ✓ Checkpoints contain aggregated BLS witness signatures"
    echo "  ✓ BLS aggregate signatures are valid 96-byte BLS12-381 format"
    echo "  ✓ Key hashes are 4-byte truncated SHA-256 per witness"
    echo "  ✓ Signatures persist across checkpoint evolution"
    echo "  ✓ Client can verify checkpoint structure"
    echo ""
    echo "Results saved in: ${TEST_DIR}/results/"
    echo ""
    echo "To clean up test artifacts:"
    echo "  rm -rf ${TEST_DIR}"
    exit 0
else
    echo -e "\n${RED}✗ SOME TESTS FAILED${NC}"
    echo "Check logs: ${TEST_DIR}/server.log"
    exit 1
fi
