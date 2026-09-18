package ctlog

import (
	"context"
	"crypto/ecdsa"

	"filippo.io/sunlight"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

var ErrEvicted = errEvicted
var ErrPoolFull = errPoolFull

type WaitEntryFunc = waitEntryFunc

func (l *Log) AddLeafToPool(e *PendingLogEntry) (WaitEntryFunc, string) {
	return l.addLeafToPool(context.Background(), e)
}

func (l *Log) Sequence() error {
	return l.sequence(context.Background())
}

func (e *PendingLogEntry) AsLogEntry(idx, timestamp int64) *sunlight.LogEntry {
	return e.asLogEntry(idx, timestamp)
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}

var seqRunning chan struct{}

func PauseSequencer() {
	seqRunning = make(chan struct{})
	testingOnlyPauseSequencing = func() {
		<-seqRunning
	}
}

func ResumeSequencer() {
	close(seqRunning)
}

// SignTreeHeadForTest signs a tree head exactly as the sequencer does.
func SignTreeHeadForTest(name string, key *ecdsa.PrivateKey, n int64, hash tlog.Hash, time int64) ([]byte, error) {
	return signTreeHead(&Config{Name: name, Key: key}, treeWithTimestamp{Tree: tlog.Tree{N: n, Hash: hash}, Time: time})
}

// CheckpointVerifierForTest is the verifier LoadLog uses on the lock checkpoint.
func CheckpointVerifierForTest(name string, key *ecdsa.PrivateKey) (note.Verifier, error) {
	signer, err := newECDSASigner(name, key, 0)
	if err != nil {
		return nil, err
	}
	return signer.(*ecdsaSigner).Verifier(), nil
}
