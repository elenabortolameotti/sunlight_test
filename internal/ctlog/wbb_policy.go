package ctlog

import (
	"fmt"
	"strconv"
	"strings"
)

type Phase string
type Role string
type EntryType string
type threshold int

const (
	PhaseSetup    Phase = "setup"
	PhaseVoting   Phase = "voting"
	PhaseTallying Phase = "tallying"

	RoleRT Role = "RT"
	RoleTT Role = "TT"
	RoleER Role = "ER"
	RoleBB Role = "BB"
	RolePM Role = "PM"

	EntryAccPubKey           EntryType = "acc_pub_key"
	EntryElectionPubKey      EntryType = "election_pub_key"
	EntryPseudonymousIDCount EntryType = "pseudonymous_id_count"
	EntryVoterIDMerkleRoot   EntryType = "voter_id_merkle_root"

	EntryBallotDigest      EntryType = "ballot_digest"
	EntryBallotMetadata    EntryType = "ballot_metadata"
	EntryCastIntendedProof EntryType = "cast_intended_proof"

	EntryEncryptedBallot   EntryType = "encrypted_ballot"
	EntryMixedBallots      EntryType = "mixed_ballots"
	EntryReEncryptionProof EntryType = "re_encryption_proof"
	EntryTallyResult       EntryType = "tally_result"
	EntryTallyProof        EntryType = "tally_proof"

	EntryPhaseTransition EntryType = "phase_transition"

	// PoC extensions:
	// the ER publishes the eligible-voter pseudonymous id list at the start
	// of tallying (paper §3.9 step 1), and commitments to ACC revocation
	// requests during the voting phase (paper §3.7.5).
	EntryEligibleVids         EntryType = "eligible_vids"
	EntryRevocationCommitment EntryType = "revocation_commitment"
	// The pseudonymous ids assigned to the registered voters, committed by
	// the ER at setup: the tally-time eligible list is audited against it.
	EntryAssignedVids EntryType = "assigned_vids"
	// The tabulation tellers' public key shares, published by the ER at
	// setup from the ceremony's output: every threshold decryption is held
	// to them, teller by teller.
	EntryTtPublicShares EntryType = "tt_public_shares"

	// The registration tellers write the credential control elements during
	// tallying (paper Sec. 3.4.2, tallying phase; Sec. 3.9 step 19).
	EntryCredentialControl EntryType = "credential_control"
)

const (
	ThresholdOne = 1
	ThresholdRT  = 2
	ThresholdTT  = 3
)

type WBBEntry struct {
	Phase     Phase
	Role      Role
	EntryType EntryType
	Threshold int
	Content   string
}

// ParseWBBEntry splits a data string into its five fields. It is at least
// as strict as the verifiers that read the log back (the auditor and the
// apps split on the first four commas and trim nothing): a field padded
// with whitespace is refused here rather than accepted and then invisible
// to every verifier; a content field with a comma in it is refused too
// (payloads are base64).
func ParseWBBEntry(s string) (WBBEntry, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		return WBBEntry{}, fmt.Errorf("invalid WBB entry: expected 5 comma-separated fields, got %d", len(parts))
	}
	for i, part := range parts[:4] {
		if part != strings.TrimSpace(part) || part == "" {
			return WBBEntry{}, fmt.Errorf("invalid WBB entry: field %d %q is empty or padded", i+1, part)
		}
	}

	threshold, err := strconv.Atoi(parts[3])
	if err != nil {
		return WBBEntry{}, fmt.Errorf("invalid WBB entry: threshold %q is not an integer", parts[3])
	}

	return WBBEntry{
		Phase:     Phase(parts[0]),
		Role:      Role(parts[1]),
		EntryType: EntryType(parts[2]),
		Threshold: threshold,
		Content:   parts[4],
	}, nil
}

func CheckWBBWritePolicy(s string) (bool, error) {
	entry, err := ParseWBBEntry(s)
	if err != nil {
		return false, err
	}

	phase := entry.Phase
	role := entry.Role
	entryType := entry.EntryType
	threshold := entry.Threshold

	if phase == PhaseSetup && role == RoleRT && entryType == EntryAccPubKey && threshold >= ThresholdRT {
		return true, nil
	}

	if phase == PhaseSetup && role == RoleER && entryType == EntryElectionPubKey && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseSetup && role == RoleER && entryType == EntryPseudonymousIDCount && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseSetup && role == RoleER && entryType == EntryAssignedVids && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseSetup && role == RoleER && entryType == EntryTtPublicShares && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseSetup && role == RoleER && entryType == EntryVoterIDMerkleRoot && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryBallotDigest && threshold == ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryBallotMetadata && threshold == ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryCastIntendedProof && threshold == ThresholdOne {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleBB && entryType == EntryEncryptedBallot && threshold == ThresholdOne {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleTT && entryType == EntryMixedBallots && threshold >= ThresholdTT {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleTT && entryType == EntryReEncryptionProof && threshold >= ThresholdTT {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleTT && entryType == EntryTallyResult && threshold >= ThresholdTT {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleTT && entryType == EntryTallyProof && threshold >= ThresholdTT {
		return true, nil
	}

	// Paper Sec. 3.4.2: "t_RT RTs which agree on the same data can write the
	// credential control elements" during tallying.
	if phase == PhaseTallying && role == RoleRT && entryType == EntryCredentialControl && threshold >= ThresholdRT {
		return true, nil
	}

	// PoC extension (P5): ER publishes the eligible-voter id list at tally start.
	if phase == PhaseTallying && role == RoleER && entryType == EntryEligibleVids && threshold >= ThresholdOne {
		return true, nil
	}

	// PoC extension (P5): ER publishes commitments to ACC revocation requests.
	// A credential can be revoked as soon as the voter has enrolled, and
	// enrollment happens inside the setup write window (the log has three
	// phases), so the commitment is accepted in setup as well as in voting.
	if (phase == PhaseSetup || phase == PhaseVoting) && role == RoleER && entryType == EntryRevocationCommitment && threshold >= ThresholdOne {
		return true, nil
	}

	// Phase manager can write phase_transition entries in any phase.
	// The transition validation happens separately in submitEntry.
	if role == RolePM && entryType == EntryPhaseTransition && threshold >= ThresholdOne {
		return true, nil
	}

	return false, fmt.Errorf("write not authorized: phase=%q role=%q entry_type=%q threshold=%d", phase, role, entryType, threshold)
}

type Permission string
type Constraint string

const (
	PermissionRead  Permission = "read"
	PermissionWrite Permission = "write"

	ConstraintPublicAccess         Constraint = "public_access"
	ConstraintOnlyAuthorized       Constraint = "only_authorized"
	ConstraintAppendOnly           Constraint = "append_only"
	ConstraintTTWriteExactlyOnce   Constraint = "tt_write_exactly_once"
	ConstraintTTSequentialOrder    Constraint = "tt_sequential_order"
	ConstraintValidSignatureProofs Constraint = "valid_signature_proofs"
)

type WBBGlobalEntry struct {
	Phase      Phase
	Role       Role
	Permission Permission
	Constraint Constraint
	Content    string
}

func ParseWBBGlobalEntry(s string) (WBBGlobalEntry, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		return WBBGlobalEntry{}, fmt.Errorf("invalid WBB global entry: expected 5 comma-separated fields, got %d", len(parts))
	}

	return WBBGlobalEntry{
		Phase:      Phase(strings.TrimSpace(parts[0])),
		Role:       Role(strings.TrimSpace(parts[1])),
		Permission: Permission(strings.TrimSpace(parts[2])),
		Constraint: Constraint(strings.TrimSpace(parts[3])),
		Content:    strings.TrimSpace(parts[4]),
	}, nil
}

func CheckWBBGlobalPolicy(s string) (bool, error) {
	entry, err := ParseWBBGlobalEntry(s)
	if err != nil {
		return false, err
	}

	if entry.Permission == PermissionRead && entry.Constraint == ConstraintPublicAccess {
		return true, nil
	}

	if entry.Permission == PermissionWrite && entry.Constraint == ConstraintOnlyAuthorized {
		return true, nil
	}

	if entry.Permission == PermissionWrite && entry.Constraint == ConstraintAppendOnly {
		return true, nil
	}

	if entry.Phase == PhaseTallying && entry.Role == RoleTT &&
		entry.Permission == PermissionWrite &&
		entry.Constraint == ConstraintTTWriteExactlyOnce {
		return true, nil
	}

	if entry.Phase == PhaseTallying && entry.Role == RoleTT &&
		entry.Permission == PermissionWrite &&
		entry.Constraint == ConstraintTTSequentialOrder {
		return true, nil
	}

	if entry.Permission == PermissionWrite && entry.Constraint == ConstraintValidSignatureProofs {
		return true, nil
	}

	return false, fmt.Errorf(
		"global policy not authorized: phase=%q role=%q permission=%q constraint=%q",
		entry.Phase,
		entry.Role,
		entry.Permission,
		entry.Constraint,
	)
}
