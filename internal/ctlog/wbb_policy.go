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

func ParseWBBEntry(s string) (WBBEntry, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		return WBBEntry{}, fmt.Errorf("invalid WBB entry: expected 5 comma-separated fields, got %d", len(parts))
	}

	threshold, err := strconv.Atoi(strings.TrimSpace(parts[3]))
	if err != nil {
		return WBBEntry{}, fmt.Errorf("invalid WBB entry: threshold %q is not an integer", strings.TrimSpace(parts[3]))
	}

	return WBBEntry{
		Phase:     Phase(strings.TrimSpace(parts[0])),
		Role:      Role(strings.TrimSpace(parts[1])),
		EntryType: EntryType(strings.TrimSpace(parts[2])),
		Threshold: threshold,
		Content:   strings.TrimSpace(parts[4]),
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

	if phase == PhaseSetup && role == RoleER && entryType == EntryVoterIDMerkleRoot && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryBallotDigest && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryBallotMetadata && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseVoting && role == RoleBB && entryType == EntryCastIntendedProof && threshold >= ThresholdOne {
		return true, nil
	}

	if phase == PhaseTallying && role == RoleBB && entryType == EntryEncryptedBallot && threshold >= ThresholdOne {
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
