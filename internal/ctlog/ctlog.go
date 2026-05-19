package ctlog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	mathrand "math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"crawshaw.io/sqlite"
	"filippo.io/sunlight"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

type Log struct {
	c     *Config
	logID [sha256.Size]byte
	m     metrics

	tree           treeWithTimestamp
	lockCheckpoint LockedCheckpoint
	edgeTiles      map[int]tileWithBytes
	cacheWrite     *sqlite.Conn

	poolMu       sync.Mutex
	currentPool  *pool
	inSequencing map[cacheHash]waitEntryFunc
	cacheRead    *sqlite.Conn

	// entityKeys maps entity IDs to their Ed25519 public keys
	// Hardcoded for now - will be configurable later
	entityKeys map[string]ed25519.PublicKey

	// Added
	entityBLSKeys map[string][]byte
}

type treeWithTimestamp struct {
	tlog.Tree
	Time int64
}

type tileWithBytes struct {
	tlog.Tile
	B []byte
}

func (t tileWithBytes) Path() string {
	return sunlight.TilePath(t.Tile)
}

func (t tileWithBytes) String() string {
	return fmt.Sprintf("%s#%d", sunlight.TilePath(t.Tile), len(t.B))
}

type Config struct {
	Name       string
	Key        *ecdsa.PrivateKey
	PoolSize   int
	Cache      string
	Backend    Backend
	Lock       LockBackend
	Log        *slog.Logger
	EntityKeys map[string]ed25519.PublicKey // Optional: override hardcoded entity keys

	// Added
	EntityBLSKeys map[string][]byte
}

var ErrLogExists = errors.New("checkpoint already exist, refusing to initialize log")

func CreateLog(ctx context.Context, config *Config) error {
	logID, err := logIDFromKey(config.Key)
	if err != nil {
		return fmt.Errorf("couldn't compute log ID: %w", err)
	}

	if _, err := config.Lock.Fetch(ctx, logID); err == nil {
		return ErrLogExists
	}
	if _, err := config.Backend.Fetch(ctx, "checkpoint"); err == nil {
		return fmt.Errorf("checkpoint missing from database but present in object storage")
	}

	cacheRead, cacheWrite, err := initCache(config.Cache)
	if err != nil {
		return fmt.Errorf("couldn't initialize cache database: %w", err)
	}
	if err := cacheRead.Close(); err != nil {
		return fmt.Errorf("couldn't close cache database: %w", err)
	}
	if err := cacheWrite.Close(); err != nil {
		return fmt.Errorf("couldn't close cache database: %w", err)
	}

	timestamp := timeNowUnixMilli()
	tree, err := hashTreeHead(0, nil, timestamp)
	if err != nil {
		return fmt.Errorf("couldn't compute empty tree head: %w", err)
	}
	checkpoint, err := signTreeHead(config, tree)
	if err != nil {
		return fmt.Errorf("couldn't sign empty tree head: %w", err)
	}

	if err := config.Lock.Create(ctx, logID, checkpoint); err != nil {
		return fmt.Errorf("couldn't create checkpoint in lock database: %w", err)
	}
	if err := config.Backend.Upload(ctx, "checkpoint", checkpoint, optsCheckpoint); err != nil {
		return fmt.Errorf("couldn't upload checkpoint: %w", err)
	}

	config.Log.InfoContext(ctx, "created log", "timestamp", timestamp,
		"logID", base64.StdEncoding.EncodeToString(logID[:]))
	return nil
}

func logIDFromKey(key *ecdsa.PrivateKey) ([sha256.Size]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("couldn't marshal public key: %w", err)
	}
	return sha256.Sum256(pkix), nil
}

func hashTreeHead(n int64, r tlog.HashReader, t int64) (treeWithTimestamp, error) {
	rootHash, err := tlog.TreeHash(n, r)
	if err != nil {
		return treeWithTimestamp{}, fmtErrorf("couldn't compute tree hash: %w", err)
	}
	return treeWithTimestamp{Tree: tlog.Tree{N: n, Hash: rootHash}, Time: t}, nil
}

func LoadLog(ctx context.Context, config *Config) (*Log, error) {
	logID, err := logIDFromKey(config.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't compute log ID: %w", err)
	}

	lock, err := config.Lock.Fetch(ctx, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint from lock database: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint", "checkpoint", lock.Bytes())
	c, timestamp, err := openCheckpoint(config, lock.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't open checkpoint: %w", err)
	}

	sth, err := config.Backend.Fetch(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint from object storage: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint from object storage", "checkpoint", sth)
	c1, _, err := openCheckpoint(config, sth)
	if err != nil {
		return nil, fmt.Errorf("couldn't open checkpoint from object storage: %w", err)
	}
	switch {
	case c1.N == c.N && c1.Hash != c.Hash:
		return nil, fmt.Errorf("checkpoint hash mismatch: %x != %x", c1.Hash, c.Hash)
	case c1.N > c.N:
		return nil, fmt.Errorf("checkpoint in object storage is newer than lock checkpoint: %d > %d", c1.N, c.N)
	case c1.N < c.N:
		config.Log.WarnContext(ctx, "checkpoint in object storage is older than lock checkpoint",
			"old_size", c1.N, "size", c.N)
		if _, err := config.Backend.Fetch(ctx, legacyStagingPath(c.Tree)); err == nil {
			return nil, fmt.Errorf("legacy staging path exists, terminate Sunlight cleanly before upgrading")
		}
		stagedUploads, err := fetchAndDecompress(ctx, config.Backend, stagingPath(c.Tree))
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch staged uploads: %w", err)
		}
		if err := applyStagedUploads(ctx, config, stagedUploads); err != nil {
			return nil, fmt.Errorf("couldn't apply staged uploads: %w", err)
		}
	}

	cacheRead, cacheWrite, err := initCache(config.Cache)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize cache database: %w", err)
	}

	edgeTiles := make(map[int]tileWithBytes)
	if c.N > 0 {
		if _, err := tlog.TileHashReader(c.Tree, &tileReader{
			fetch: func(key string) ([]byte, error) {
				return config.Backend.Fetch(ctx, key)
			},
			saveTiles: func(tiles []tlog.Tile, data [][]byte) {
				for i, tile := range tiles {
					if t, ok := edgeTiles[tile.L]; !ok || t.N < tile.N || (t.N == tile.N && t.W < tile.W) {
						edgeTiles[tile.L] = tileWithBytes{tile, data[i]}
					}
				}
			}}).ReadHashes([]int64{tlog.StoredHashIndex(0, c.N-1)}); err != nil {
			return nil, fmt.Errorf("couldn't fetch right edge tiles: %w", err)
		}

		dataTile := edgeTiles[0]
		dataTile.L = -1
		dataTile.B, err = fetchAndDecompress(ctx, config.Backend, dataTile.Path())
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch right edge data tile: %w", err)
		}
		edgeTiles[-1] = dataTile

		b := edgeTiles[-1].B
		start := sunlight.TileWidth * dataTile.N
		for i := start; i < start+int64(dataTile.W); i++ {
			e, rest, err := sunlight.ReadTileLeaf(b)
			if err != nil {
				return nil, fmt.Errorf("invalid data tile %v: %w", dataTile.Tile, err)
			}
			b = rest

			got := tlog.RecordHash(e.MerkleTreeLeaf())
			exp, err := tlog.HashFromTile(edgeTiles[0].Tile, edgeTiles[0].B, tlog.StoredHashIndex(0, i))
			if err != nil {
				return nil, fmt.Errorf("couldn't extract hash for leaf %d: %w", i, err)
			}
			if got != exp {
				return nil, fmt.Errorf("tile leaf entry %d hashes to %v, level 0 hash is %v", i, got, exp)
			}
		}
	}
	for _, t := range edgeTiles {
		config.Log.DebugContext(ctx, "edge tile", "tile", t)
	}

	config.Log.InfoContext(ctx, "loaded log", "logID", base64.StdEncoding.EncodeToString(logID[:]),
		"size", c.N, "timestamp", timestamp)

	m := initMetrics()
	m.TreeSize.Set(float64(c.N))
	m.TreeTime.Set(float64(timestamp))

	// Initialize entity keys - use config if provided, otherwise use hardcoded defaults
	var entityKeys map[string]ed25519.PublicKey
	if config.EntityKeys != nil {
		entityKeys = config.EntityKeys
	} else {
		entityKeys = map[string]ed25519.PublicKey{
			"witness-1": mustDecodeKey("2f8c2b3e4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"),
			"client-a":  mustDecodeKey("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"),
		}
	}

	// Initialize BLS entity keys for aggregate signatures.
	// These are public keys only: the server verifies aggregate signatures,
	// it does not sign on behalf of RT/TT entities.
	var entityBLSKeys map[string][]byte
	if config.EntityBLSKeys != nil {
		entityBLSKeys = config.EntityBLSKeys
	} else {
		entityBLSKeys = map[string][]byte{}
	}

	return &Log{
		c:              config,
		logID:          logID,
		m:              m,
		tree:           treeWithTimestamp{c.Tree, timestamp},
		lockCheckpoint: lock,
		edgeTiles:      edgeTiles,
		cacheRead:      cacheRead,
		currentPool:    newPool(),
		cacheWrite:     cacheWrite,
		entityKeys:     entityKeys,
		entityBLSKeys:  entityBLSKeys,
	}, nil
}

func mustDecodeKey(hexStr string) ed25519.PublicKey {
	// TODO: In production, decode actual hex keys here
	// For now, return a dummy 32-byte key
	return make([]byte, 32)
}

func openCheckpoint(config *Config, b []byte) (sunlight.Checkpoint, int64, error) {
	// The input is a signed note. First, we need to extract just the checkpoint text
	// (before the blank line and signatures), then parse it.
	s := string(b)

	// Find the blank line that separates the text from the signatures
	idx := strings.Index(s, "\n\n")
	if idx == -1 {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("malformed signed note: no signature separator")
	}

	checkpointText := s[:idx+1] // Include the trailing newline

	c, err := sunlight.ParseCheckpoint(checkpointText)
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't parse checkpoint: %w", err)
	}

	if c.Origin != config.Name {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("checkpoint name is %q, not %q", c.Origin, config.Name)
	}
	if c.Extension != "" {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("unexpected checkpoint extension %q", c.Extension)
	}

	timestamp := timeNowUnixMilli()
	return c, timestamp, nil
}

var timeNowUnixMilli = func() int64 { return time.Now().UnixMilli() }

func (l *Log) AcceptingSubmissions() bool {
	return true
}

type Backend interface {
	Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) error
	Fetch(ctx context.Context, key string) ([]byte, error)
	Discard(ctx context.Context, key string) error
	Metrics() []prometheus.Collector
}

type UploadOptions struct {
	ContentType string
	Compressed  bool
	Immutable   bool
}

var optsHashTile = &UploadOptions{Immutable: true}
var optsDataTile = &UploadOptions{Compressed: true, Immutable: true}
var optsStaging = &UploadOptions{Compressed: true, Immutable: true}
var optsCheckpoint = &UploadOptions{ContentType: "text/plain; charset=utf-8"}

var ErrLogNotFound = errors.New("log not found")

type LockBackend interface {
	Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error)
	Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error)
	Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error
}

type LockedCheckpoint interface {
	Bytes() []byte
}

type tileReader struct {
	fetch     func(key string) ([]byte, error)
	saveTiles func(tiles []tlog.Tile, data [][]byte)
}

func (r *tileReader) Height() int {
	return sunlight.TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.fetch(sunlight.TilePath(t))
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) { r.saveTiles(tiles, data) }

type PendingLogEntry struct {
	Data []byte
}

func (e *PendingLogEntry) asLogEntry(idx, timestamp int64) *sunlight.LogEntry {
	return &sunlight.LogEntry{
		Data:      e.Data,
		LeafIndex: idx,
		Timestamp: timestamp,
	}
}

type cacheHash [16]byte

func computeCacheHash(data []byte) cacheHash {
	h := sha256.Sum256(data)
	return cacheHash(h[:16])
}

type pool struct {
	pendingLeaves  []*PendingLogEntry
	byHash         map[cacheHash]waitEntryFunc
	lowPriority    map[int]func()
	done           chan struct{}
	err            error
	firstLeafIndex int64
	timestamp      int64
}

type waitEntryFunc func(ctx context.Context) (*sunlight.LogEntry, error)

func newPool() *pool {
	return &pool{
		done:        make(chan struct{}),
		byHash:      make(map[cacheHash]waitEntryFunc),
		lowPriority: make(map[int]func()),
	}
}

var errPoolFull = fmtErrorf("rate limited")
var errEvicted = fmtErrorf("evicted to make way for higher priority leaves")

func (l *Log) addLeafToPool(ctx context.Context, leaf *PendingLogEntry) (f waitEntryFunc, source string) {
	l.poolMu.Lock()
	defer l.poolMu.Unlock()
	p := l.currentPool
	if err := p.err; err != nil {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return nil, err
		}, "closed"
	}
	h := computeCacheHash(leaf.Data)
	if f, ok := p.byHash[h]; ok {
		return f, "pool"
	}
	if f, ok := l.inSequencing[h]; ok {
		return f, "pool"
	}
	if leafEntry, err := l.cacheGet(leaf.Data); err != nil {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return nil, fmtErrorf("deduplication cache get failed: %w", err)
		}, "cache"
	} else if leafEntry != nil {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return leafEntry, nil
		}, "cache"
	}
	n := len(p.pendingLeaves)
	if l.c.PoolSize > 0 && n >= l.c.PoolSize {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return nil, errPoolFull
		}, "ratelimit"
	}
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	f = func(ctx context.Context) (*sunlight.LogEntry, error) {
		select {
		case <-ctx.Done():
			return nil, fmtErrorf("context canceled while waiting for sequencing: %w", ctx.Err())
		case <-p.done:
			if err := ctx.Err(); err != nil {
				return nil, fmtErrorf("context canceled while waiting for sequencing: %w", err)
			}
			if p.err != nil {
				return nil, p.err
			}
			if p.timestamp == 0 {
				panic("internal error: pool is ready but result is missing")
			}
			idx := p.firstLeafIndex + int64(n)
			return leaf.asLogEntry(idx, p.timestamp), nil
		}
	}
	p.byHash[h] = f
	return f, "sequencer"
}

type SunsetLogError struct {
	FinalTree      tlog.Tree
	FinalTimestamp int64
}

func (SunsetLogError) Error() string {
	return "the log is read-only"
}

func (l *Log) RunSequencer(ctx context.Context, period time.Duration) (err error) {
	defer func() {
		l.poolMu.Lock()
		defer l.poolMu.Unlock()
		l.currentPool.err = err
		close(l.currentPool.done)
	}()

	if !testing.Testing() {
		time.Sleep(time.Duration(mathrand.Int64N(int64(period))))
	}

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := l.sequence(ctx); err != nil {
				return err
			}
		}
	}
}

const sequenceTimeout = 15 * time.Second
const strictTimeout = 1 * time.Second

var errFatal = errors.New("fatal sequencing error")

func (l *Log) sequence(ctx context.Context) error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = newPool()
	l.inSequencing = p.byHash
	l.poolMu.Unlock()

	err := l.sequencePool(ctx, p)

	l.poolMu.Lock()
	l.inSequencing = nil
	l.poolMu.Unlock()

	return err
}

func (l *Log) sequencePool(ctx context.Context, p *pool) (err error) {
	oldSize := l.tree.N
	start := time.Now()
	seqLog := l.c.Log.With("old_tree_size", oldSize,
		"entries", len(p.pendingLeaves), "start", start)
	defer prometheus.NewTimer(l.m.SeqDuration).ObserveDuration()
	defer func() {
		if err != nil {
			p.err = err
			seqLog.ErrorContext(ctx, "pool sequencing failed",
				"elapsed", time.Since(start), "err", err)
			l.m.SeqCount.With(prometheus.Labels{"error": errorCategory(err)}).Inc()

			if !errors.Is(err, errFatal) {
				err = nil
			}
		} else {
			l.m.SeqCount.With(prometheus.Labels{"error": ""}).Inc()
		}
		l.m.SeqPoolSize.Observe(float64(len(p.pendingLeaves)))

		close(p.done)
	}()

	ctx, cancel := context.WithTimeout(ctx, sequenceTimeout)
	defer cancel()

	timestamp := timeNowUnixMilli()
	if timestamp <= l.tree.Time {
		return fmt.Errorf("%w: time did not progress! %d -> %d", errFatal, l.tree.Time, timestamp)
	}

	var tileUploads []*uploadAction
	edgeTiles := maps.Clone(l.edgeTiles)
	var dataTile []byte
	if t, ok := edgeTiles[-1]; ok && t.W < sunlight.TileWidth {
		dataTile = bytes.Clone(t.B)
	}
	newHashes := make(map[int64]tlog.Hash)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	var sequencedLeaves []*sunlight.LogEntry
	for _, leaf := range p.pendingLeaves {
		leaf := leaf.asLogEntry(n, timestamp)
		sequencedLeaves = append(sequencedLeaves, leaf)
		oldTileSize := len(dataTile)
		dataTile = sunlight.AppendTileLeaf(dataTile, leaf)
		l.m.SeqLeafSize.Observe(float64(len(dataTile) - oldTileSize))

		hashes, err := tlog.StoredHashes(n, leaf.MerkleTreeLeaf(), hashReader)
		if err != nil {
			return fmtErrorf("couldn't compute new hashes for leaf %d: %w", n, err)
		}
		for i, h := range hashes {
			id := tlog.StoredHashIndex(0, n) + int64(i)
			newHashes[id] = h
		}

		n++

		if n%sunlight.TileWidth == 0 {
			tile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			edgeTiles[-1] = tileWithBytes{tile, dataTile}

			gzipData, err := compress(dataTile)
			if err != nil {
				return fmtErrorf("couldn't compress data tile: %w", err)
			}
			l.c.Log.DebugContext(ctx, "staging full data tile", "tree_size", n,
				"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))
			l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
			l.m.SeqDataTileGzipSize.Observe(float64(len(gzipData)))

			tileUploads = append(tileUploads, &uploadAction{
				sunlight.TilePath(tile), gzipData, optsDataTile})
			dataTile = nil
		}
	}

	if n != l.tree.N && n%sunlight.TileWidth != 0 {
		tile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, n-1))
		tile.L = -1
		edgeTiles[-1] = tileWithBytes{tile, dataTile}
		gzipData, err := compress(dataTile)
		if err != nil {
			return fmtErrorf("couldn't compress data tile: %w", err)
		}
		l.c.Log.DebugContext(ctx, "staging partial data tile", "tree_size", n,
			"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))
		l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
		l.m.SeqDataTileGzipSize.Observe(float64(len(gzipData)))
		tileUploads = append(tileUploads, &uploadAction{
			sunlight.TilePath(tile), gzipData, optsDataTile})
	}

	tiles := tlog.NewTiles(sunlight.TileHeight, l.tree.N, n)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return fmtErrorf("couldn't generate tile %v: %w", tile, err)
		}
		if t0, ok := edgeTiles[tile.L]; !ok || t0.N < tile.N || (t0.N == tile.N && t0.W < tile.W) {
			edgeTiles[tile.L] = tileWithBytes{tile, data}
		}
		l.c.Log.DebugContext(ctx, "staging tree tile", "old_tree_size", oldSize,
			"tree_size", n, "tile", tile, "size", len(data))
		tileUploads = append(tileUploads, &uploadAction{
			sunlight.TilePath(tile), data, optsHashTile})
	}

	if testingOnlyPauseSequencing != nil {
		testingOnlyPauseSequencing()
	}

	tree, err := hashTreeHead(n, hashReader, timestamp)
	if err != nil {
		return fmtErrorf("couldn't compute tree head: %w", err)
	}

	stagedUploads, err := marshalStagedUploads(tileUploads)
	if err != nil {
		return fmtErrorf("couldn't marshal staged uploads: %w", err)
	}
	stagingPath := stagingPath(tree.Tree)
	if len(tileUploads) > 0 {
		gzipData, err := compress(stagedUploads)
		if err != nil {
			return fmtErrorf("couldn't compress staged uploads: %w", err)
		}
		l.c.Log.DebugContext(ctx, "uploading staged tiles", "old_tree_size", oldSize,
			"tree_size", tree.N, "path", stagingPath, "size", len(stagedUploads), "gzip_size", len(gzipData))
		ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
		defer cancel()
		if err := l.c.Backend.Upload(ctxStrict, stagingPath, gzipData, optsStaging); err != nil {
			return fmtErrorf("couldn't upload staged tiles: %w", err)
		}
	}

	checkpoint, err := signTreeHead(l.c, tree)
	if err != nil {
		return fmtErrorf("couldn't sign checkpoint: %w", err)
	}
	l.c.Log.DebugContext(ctx, "uploading checkpoint", "size", len(checkpoint))
	newLock, err := l.c.Lock.Replace(ctx, l.lockCheckpoint, checkpoint)
	if err != nil {
		return fmt.Errorf("%w: couldn't upload checkpoint to database: %w", errFatal, err)
	}

	p.timestamp = timestamp
	p.firstLeafIndex = l.tree.N
	l.tree = tree
	l.lockCheckpoint = newLock
	l.edgeTiles = edgeTiles

	if err := applyStagedUploads(ctx, l.c, stagedUploads); err != nil {
		return fmtErrorf("%w: couldn't upload a tile: %w", errFatal, err)
	}

	ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
	defer cancel()
	if err := l.c.Backend.Upload(ctxStrict, "checkpoint", checkpoint, optsCheckpoint); err != nil {
		return fmtErrorf("couldn't upload checkpoint to object storage: %w", err)
	}

	if len(tileUploads) > 0 {
		if err := l.c.Backend.Discard(ctx, stagingPath); err != nil {
			l.c.Log.ErrorContext(ctx, "staging bundle discard failed",
				"tree_size", tree.N, "err", err)
			l.m.StagingDiscardErrors.Inc()
		}
	}

	if err := l.cachePut(sequencedLeaves); err != nil {
		l.c.Log.ErrorContext(ctx, "cache put failed",
			"tree_size", tree.N, "entries", len(p.pendingLeaves), "err", err)
		l.m.CachePutErrors.Inc()
	}

	for _, t := range edgeTiles {
		l.c.Log.DebugContext(ctx, "edge tile", "tile", t)
	}
	seqLog.Info("sequenced pool", "tree_size", tree.N,
		"tiles", len(tileUploads), "timestamp", timestamp,
		"elapsed", time.Since(start))
	l.m.SeqTiles.Add(float64(len(tileUploads)))
	l.m.TreeSize.Set(float64(tree.N))
	l.m.TreeTime.Set(float64(timestamp) / 1000)

	return nil
}

var testingOnlyPauseSequencing func()

type uploadAction struct {
	key  string
	data []byte
	opts *UploadOptions
}

func marshalStagedUploads(uploads []*uploadAction) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, u := range uploads {
		opts, err := json.Marshal(u.opts)
		if err != nil {
			return nil, fmtErrorf("couldn't marshal upload options: %w", err)
		}
		if err := writer.WriteHeader(&tar.Header{
			Name:       u.key,
			Size:       int64(len(u.data)),
			PAXRecords: map[string]string{"SUNLIGHT.opts": string(opts)},
		}); err != nil {
			return nil, fmtErrorf("error writing tar header: %w", err)
		}
		if _, err := writer.Write(u.data); err != nil {
			return nil, fmtErrorf("error writing tar data: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmtErrorf("error closing tar writer: %w", err)
	}
	return buffer.Bytes(), nil
}

func applyStagedUploads(ctx context.Context, config *Config, stagedUploads []byte) error {
	g, gctx := errgroup.WithContext(ctx)
	reader := tar.NewReader(bytes.NewReader(stagedUploads))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmtErrorf("error reading tar header: %w", err)
		}
		key := header.Name
		optsBytes, ok := header.PAXRecords["SUNLIGHT.opts"]
		if !ok {
			return fmtErrorf("missing SUNLIGHT.opts in tar header")
		}
		opts := &UploadOptions{}
		if err := json.Unmarshal([]byte(optsBytes), opts); err != nil {
			return fmtErrorf("couldn't unmarshal upload options: %w", err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmtErrorf("error reading tar data: %w", err)
		}
		g.Go(func() error {
			return config.Backend.Upload(gctx, key, data, opts)
		})
	}
	return g.Wait()
}

func stagingPath(tree tlog.Tree) string {
	return fmt.Sprintf("staging/%d-%s", tree.N, hex.EncodeToString(tree.Hash[:]))
}

func legacyStagingPath(tree tlog.Tree) string {
	n := tree.N
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}
	return fmt.Sprintf("staging/%s/%s", nStr, hex.EncodeToString(tree.Hash[:]))
}

func signTreeHead(c *Config, tree treeWithTimestamp) (checkpoint []byte, err error) {
	// Create a simple checkpoint (no extension for now)
	cp := sunlight.Checkpoint{
		Origin: c.Name,
		Tree:   tlog.Tree{N: tree.N, Hash: tree.Hash},
	}

	// Format the checkpoint text
	text := sunlight.FormatCheckpoint(cp)

	// Create a simple ECDSA signer
	signer, err := newECDSASigner(c.Name, c.Key, tree.Time)
	if err != nil {
		return nil, fmt.Errorf("couldn't create signer: %w", err)
	}

	// Sign the checkpoint
	signedNote, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		return nil, fmt.Errorf("couldn't sign checkpoint: %w", err)
	}

	return signedNote, nil
}

// ecdsaSigner implements note.Signer for ECDSA keys
type ecdsaSigner struct {
	name      string
	keyHash   uint32
	key       *ecdsa.PrivateKey
	timestamp int64
}

func newECDSASigner(name string, key *ecdsa.PrivateKey, timestamp int64) (note.Signer, error) {
	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{0x03}) // Simple ECDSA key type
	h.Write(pkix)
	keyHash := binary.BigEndian.Uint32(h.Sum(nil))

	return &ecdsaSigner{
		name:      name,
		keyHash:   keyHash,
		key:       key,
		timestamp: timestamp,
	}, nil
}

func (s *ecdsaSigner) Name() string    { return s.name }
func (s *ecdsaSigner) KeyHash() uint32 { return s.keyHash }

func (s *ecdsaSigner) Sign(msg []byte) ([]byte, error) {
	// Simple signature: timestamp + ECDSA signature
	digest := sha256.Sum256(msg)
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}

	// Encode as: timestamp (8 bytes) + r (32 bytes) + s (32 bytes)
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint64(s.timestamp))
	buf.Write(r.Bytes())
	buf.Write(sig.Bytes())

	return buf.Bytes(), nil
}

func (s *ecdsaSigner) Verifier() note.Verifier {
	return &ecdsaVerifier{
		name:    s.name,
		keyHash: s.keyHash,
		key:     &s.key.PublicKey,
	}
}

type ecdsaVerifier struct {
	name    string
	keyHash uint32
	key     *ecdsa.PublicKey
}

func (v *ecdsaVerifier) Name() string    { return v.name }
func (v *ecdsaVerifier) KeyHash() uint32 { return v.keyHash }
func (v *ecdsaVerifier) Verify(msg, sig []byte) bool {
	if len(sig) < 8 {
		return false
	}
	// Skip timestamp (first 8 bytes)
	sigData := sig[8:]
	mid := len(sigData) / 2
	r := new(big.Int).SetBytes(sigData[:mid])
	s := new(big.Int).SetBytes(sigData[mid:])

	digest := sha256.Sum256(msg)
	return ecdsa.Verify(v.key, digest[:], r, s)
}

func (l *Log) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			if h, ok := overlay[id]; ok {
				list = append(list, h)
				continue
			}
			t := l.edgeTiles[tlog.TileForIndex(sunlight.TileHeight, id).L]
			h, err := tlog.HashFromTile(t.Tile, t.B, id)
			if err != nil {
				return nil, fmt.Errorf("index %d not in overlay and %w", id, err)
			}
			list = append(list, h)
		}
		return list, nil
	}
}

func compress(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxCompressRatio = 100

func fetchAndDecompress(ctx context.Context, backend Backend, key string) ([]byte, error) {
	data, err := backend.Fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	maxSize := int64(len(data)) * maxCompressRatio
	return io.ReadAll(io.LimitReader(r, maxSize))
}
