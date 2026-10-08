package ctlog_test

// The per-writer staging bound
// (writerPendingLocked / errStagingFull) and the threshold-1 rule for ballot
// boxes must never refuse a publication the PoC makes honestly. The PoC's
// tally driver (referendum-poc src/actors/admin.rs `flush_publications`,
// `submit_cosigned_and_wait`) submits its co-signed artifacts ONE AT A TIME:
// every partial of an entry, then it waits until the board has sequenced the
// entry before it signs the next. TT artifacts declare threshold 3 = all
// three tabulation tellers (published at once on the third partial); the RT
// `credential_control` artifact declares t_RT = 2 of 3 (published after the
// grace period, or at once when the third partial arrives; a third partial
// after publication becomes a `ref:N` leaf). A run cut off part-way is
// resumed from its saved outbox: the same data, re-signed with fresh
// timestamps - partials already staged answer 409 and count as delivered.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
)

// waitPublishedForTest polls /entries?start=*from until an entry carrying data
// is sequenced (what `submit_cosigned_and_wait` does after its partials),
// then moves *from past it: the reading stays incremental.
func waitPublishedForTest(t *testing.T, server *httptest.Server, from *int64, data string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, body, _ := pocGet(t, fmt.Sprintf("%s/entries?start=%d", server.URL, *from))
		var entries pocEntriesResponse
		if err := json.Unmarshal(body, &entries); err == nil {
			for _, e := range entries.Entries {
				var signed ctlog.SignedEntry
				if json.Unmarshal(e.Entry, &signed) == nil && string(signed.Data) == data {
					*from = e.LeafIndex + 1
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("entry was not published in time: %.60s...", data)
}

func TestPoCHonestTallySequenceNeverHitsTheStagingBound(t *testing.T) {
	ids := []string{"TT-1", "TT-2", "TT-3", "RT-1", "RT-2", "RT-3", "BB-1", "BB-2"}
	pubs, privs := pocKeys(t, ids...)
	server, log := startPoCLogWithLog(t, pubs, nil, func(c *ctlog.Config) {
		c.GracePeriod = 100 * time.Millisecond // the PoC's grace_period_ms
	})
	// Data as large as one submission can carry: the body cap is 128 KiB
	// (default) and the data travels base64-encoded inside the JSON body.
	// 95 000 bytes of data is ~127 000 bytes of body; the per-writer byte
	// bound (4 x 128 KiB) admits five such entries pending at once.
	payload := func(kind string, i int) string {
		head := fmt.Sprintf("%s-%04d-", kind, i)
		return head + strings.Repeat("x", 95000-len(head))
	}
	ts := time.Now().UnixMilli()
	next := func() int64 { ts++; return ts }
	submitted := map[string]int{}
	var from int64

	// MaxPendingPerWriter + 8 artifacts per teller, each near the size cap:
	// 72 x 95 KB = 6.8 MB per writer in all - past both bounds had the
	// published ones been counted.
	n := ctlog.MaxPendingPerWriter + 8
	for i := 0; i < n; i++ {
		// A tabulation tellers' artifact, threshold 3 (all three sign).
		tt := "tallying,TT,mixed_ballots,3," + payload("tt", i)
		stamp := next()
		for j, id := range []string{"TT-1", "TT-2", "TT-3"} {
			code, body := pocSubmit(t, server, tt, id, stamp, privs[id])
			want := http.StatusAccepted
			if j == 2 {
				want = http.StatusOK
			}
			if code != want {
				t.Fatalf("TT artifact %d, %s: expected %d, got %d: %s", i, id, want, code, body)
			}
			submitted[id]++
		}
		waitPublishedForTest(t, server, &from, tt)

		// The registration tellers' artifact, threshold t_RT = 2 of 3. Every
		// third one RT-3 refuses to co-sign (README row 21: the entry goes
		// out under the signatures it has); every fifth one RT-3's partial
		// arrives after publication (a `ref:N` leaf).
		rt := "tallying,RT,credential_control,2," + payload("rt", i)
		stamp = next()
		for _, id := range []string{"RT-1", "RT-2"} {
			if code, body := pocSubmit(t, server, rt, id, stamp, privs[id]); code != http.StatusAccepted && code != http.StatusOK {
				t.Fatalf("RT artifact %d, %s: expected 202/200, got %d: %s", i, id, code, body)
			}
			submitted[id]++
		}
		switch {
		case i%3 == 0: // RT-3 refused: published after the grace period
			waitPublishedForTest(t, server, &from, rt)
		case i%5 == 0: // RT-3 late: after publication, a ref leaf
			waitPublishedForTest(t, server, &from, rt)
			if code, body := pocSubmit(t, server, rt, "RT-3", stamp, privs["RT-3"]); code != http.StatusOK && code != http.StatusConflict {
				t.Fatalf("RT artifact %d, late RT-3: expected 200/409, got %d: %s", i, code, body)
			}
			submitted["RT-3"]++
		default:
			if code, body := pocSubmit(t, server, rt, "RT-3", stamp, privs["RT-3"]); code != http.StatusOK && code != http.StatusAccepted && code != http.StatusConflict {
				t.Fatalf("RT artifact %d, RT-3: expected 200/202/409, got %d: %s", i, code, body)
			}
			submitted["RT-3"]++
			waitPublishedForTest(t, server, &from, rt)
		}

		// A box's release, single-signed at threshold 1 (as the driver
		// writes it on the box's behalf).
		bb := fmt.Sprintf("BB-%d", 1+i%2)
		rel := "tallying,BB,encrypted_ballot,1," + payload("bb", i)
		if code, body := pocSubmit(t, server, rel, bb, next(), privs[bb]); code != http.StatusOK {
			t.Fatalf("release %d by %s: expected 200, got %d: %s", i, bb, code, body)
		}
	}

	// A run cut off after TT-1's partial of the next artifact, then resumed
	// from its saved outbox: the same data, signed again with fresh
	// timestamps (admin.rs `Resigner`). TT-1's staged partial answers 409 and
	// counts as delivered; the entry completes.
	cut := "tallying,TT,tally_proof,3," + payload("cut", 0)
	if code, body := pocSubmit(t, server, cut, "TT-1", next(), privs["TT-1"]); code != http.StatusAccepted {
		t.Fatalf("cut-off partial: expected 202, got %d: %s", code, body)
	}
	stamp := next()
	for j, id := range []string{"TT-1", "TT-2", "TT-3"} {
		code, body := pocSubmit(t, server, cut, id, stamp, privs[id])
		want := []int{http.StatusConflict, http.StatusAccepted, http.StatusOK}[j]
		if code != want {
			t.Fatalf("resumed %s: expected %d, got %d: %s", id, want, code, body)
		}
	}
	waitPublishedForTest(t, server, &from, cut)

	// Nothing an honest writer submitted is left pending.
	if got := log.StagingLenForTest(); got != 2*n+1 {
		t.Errorf("staging holds %d entries, expected the %d published threshold entries", got, 2*n+1)
	}
	t.Logf("partials accepted per writer: %v", submitted)
}

// The bound counts an entry until it is PUBLISHED, not until it reaches its
// threshold (README row 36 says "staged entries that have not reached their
// threshold"). Recorded: an honest writer never has two entries in flight.
// What an ABANDONED entry costs an honest writer: a run cut off part-way
// whose outbox is not resumed (the pipeline re-run produces new data) leaves
// the old partial staged until a board restart (README row 15). With
// near-cap entries the byte bound is reached after five abandoned ones.
func TestPoCAbandonedPartialsReachTheByteBoundAfterFive(t *testing.T) {
	pubs, privs := pocKeys(t, "TT-1", "TT-2", "TT-3")
	server, _ := startPoCLogWithLog(t, pubs, nil, nil)
	payload := func(i int) string {
		head := fmt.Sprintf("abandoned-%04d-", i)
		return "tallying,TT,mixed_ballots,3," + head + strings.Repeat("x", 95000-len(head))
	}
	ts := time.Now().UnixMilli()
	accepted := 0
	for i := 0; i < 10; i++ {
		ts++
		code, _ := pocSubmit(t, server, payload(i), "TT-1", ts, privs["TT-1"])
		if code == http.StatusServiceUnavailable {
			break
		}
		if code != http.StatusAccepted {
			t.Fatalf("abandoned partial %d: expected 202, got %d", i, code)
		}
		accepted++
	}
	t.Logf("near-cap partials TT-1 could leave pending before 503: %d", accepted)
	if accepted != 5 {
		t.Fatalf("expected 5, got %d", accepted)
	}
}

// The partial that completes a co-signed entry is cut off by the network
// while the board waits for the sequencer: the entry is in the pool and IS
// sequenced, so it must not be rolled back to "pending" - it would then count
// against every co-signer's staging bound until the board restarts.
func TestPoCCutCompletingPartialLeavesNothingPending(t *testing.T) {
	ids := []string{"TT-1", "TT-2", "TT-3"}
	pubs, privs := pocKeys(t, ids...)
	server, log := startPoCLogWithLog(t, pubs, nil, nil)
	data := "tallying,TT,mixed_ballots,3,cut"
	now := time.Now().UnixMilli()
	for _, id := range ids[:2] {
		if code, body := pocSubmit(t, server, data, id, now, privs[id]); code != http.StatusAccepted {
			t.Fatalf("%s: expected 202, got %d: %s", id, code, body)
		}
	}
	ctlog.PauseSequencer()
	entry := createSignedEntry(t, []byte(data), "TT-3", now, privs["TT-3"])
	raw, err := json.Marshal(entry)
	if err != nil {
		ctlog.ResumeSequencer()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/submit", bytes.NewReader(raw))
	if err != nil {
		ctlog.ResumeSequencer()
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		ctlog.ResumeSequencer()
		t.Fatalf("the completing partial was not cut off: HTTP %d", resp.StatusCode)
	}
	// Let the board notice the closed connection before it may sequence.
	time.Sleep(200 * time.Millisecond)
	ctlog.ResumeSequencer()
	var from int64
	waitPublishedForTest(t, server, &from, data)
	for _, id := range ids {
		if n, size := log.WriterPendingForTest(id); n != 0 {
			t.Errorf("%s: %d pending entries (%d bytes) after the entry was published", id, n, size)
		}
	}
}
