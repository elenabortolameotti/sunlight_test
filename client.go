package sunlight

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// Client is a log client that fetches and authenticates tiles,
// and exposes log entries as a Go iterator.
type Client struct {
	c   *torchwood.Client
	r   torchwood.TileReader
	cc  *ClientConfig
	err error
}

// ClientConfig is the configuration for a [Client].
type ClientConfig struct {
	// MonitoringPrefix is the monitoring prefix URL.
	//
	// If the MonitoringPrefix has schema "file://", Client will read tiles from
	// the local filesystem, and most other settings will be ignored.
	//
	// If it has schema "gzip+file://", the data tiles are expected to be
	// gzip-compressed.
	MonitoringPrefix string

	// PublicKey is the public key of the log, used to verify checkpoints.
	PublicKey interface{}

	// HTTPClient is the HTTP client used to fetch tiles. If nil, a client is
	// created with default timeouts and settings.
	HTTPClient *http.Client

	// UserAgent is the User-Agent string used for HTTP requests. It must be
	// set, and it must include an email address and/or an HTTPS URL.
	UserAgent string

	// Timeout is how long the Entries iterator can take to yield an entry.
	// This includes any Retry-After waits. If zero, it defaults to five minutes.
	Timeout time.Duration

	// ConcurrencyLimit is the maximum number of concurrent requests
	// made by the Client. If zero, there is no limit.
	ConcurrencyLimit int

	// Cache, if set, is a directory where the client will permanently cache
	// verified non-partial tiles, following the same structure as the URLs.
	Cache string

	// Logger is the logger used to log errors and progress.
	// If nil, log lines are discarded.
	Logger *slog.Logger
}

// NewClient creates a new [Client].
func NewClient(config *ClientConfig) (*Client, error) {
	if schema, path, ok := strings.Cut(config.MonitoringPrefix, "://"); ok &&
		(schema == "file" || schema == "gzip+file") {
		if config.Cache != "" {
			return nil, errors.New("sunlight: permanent cache cannot be used with file://")
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, fmt.Errorf("sunlight: failed to open file:// monitoring prefix: %w", err)
		}
		tileFS := root.FS()
		options := []torchwood.TileFSOption{torchwood.WithTileFSTilePath(TilePath)}
		if schema == "gzip+file" {
			options = append(options, torchwood.WithGzipDataTiles())
		}
		tileReader, err := torchwood.NewTileFS(tileFS, options...)
		if err != nil {
			return nil, fmt.Errorf("sunlight: failed to create file:// tile reader: %w", err)
		}
		client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry))
		if err != nil {
			return nil, fmt.Errorf("sunlight: failed to create file:// client: %w", err)
		}
		return &Client{c: client, r: tileReader, cc: config}, nil
	}

	if config.UserAgent == "" {
		return nil, errors.New("sunlight: missing UserAgent")
	}
	if !strings.Contains(config.UserAgent, "@") &&
		!strings.Contains(config.UserAgent, "+https://") {
		return nil, errors.New("sunlight: UserAgent must include an email address or HTTPS URL (+https://example.com)")
	}
	fetcher, err := torchwood.NewTileFetcher(config.MonitoringPrefix,
		torchwood.WithTilePath(TilePath),
		torchwood.WithHTTPClient(config.HTTPClient),
		torchwood.WithUserAgent(config.UserAgent+" sunlight/"+libraryVersion()),
		torchwood.WithConcurrencyLimit(config.ConcurrencyLimit),
		torchwood.WithTileFetcherLogger(config.Logger))
	if err != nil {
		return nil, err
	}
	var tileReader torchwood.TileReader = fetcher
	if config.Cache != "" {
		tileReader, err = torchwood.NewPermanentCache(tileReader, config.Cache,
			torchwood.WithPermanentCacheLogger(config.Logger),
			torchwood.WithPermanentCacheTilePath(TilePath))
		if err != nil {
			return nil, err
		}
	}
	client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry),
		torchwood.WithTimeout(config.Timeout))
	if err != nil {
		return nil, err
	}
	return &Client{c: client, r: tileReader, cc: config}, nil
}

// TileReader returns the underlying [torchwood.TileReader].
func (c *Client) TileReader() torchwood.TileReader {
	return c.r
}

func cutEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	e, rest, err := ReadTileLeaf(tile)
	if err != nil {
		return nil, tlog.Hash{}, nil, err
	}
	rh = tlog.RecordHash(e.MerkleTreeLeaf())
	entry = tile[:len(tile)-len(rest)]
	return entry, rh, rest, nil
}

// Err returns the error encountered by the latest [Client.Entries] call.
func (c *Client) Err() error {
	if c.err != nil {
		return c.err
	}
	if err := c.c.Err(); err != nil {
		return err
	}
	return nil
}

// Entries returns an iterator that yields entries from the given tree, starting
// at the given index. The first item in the yielded pair is the overall entry
// index in the log, starting at start.
//
// The provided tree should have been verified by the caller, for example using
// [Client.Checkpoint].
//
// Callers must check [Client.Err] after the iteration breaks.
func (c *Client) Entries(ctx context.Context, tree tlog.Tree, start int64) iter.Seq2[int64, *LogEntry] {
	c.err = nil
	return func(yield func(int64, *LogEntry) bool) {
		for i, e := range c.c.Entries(ctx, tree, start) {
			entry, rest, err := ReadTileLeaf(e)
			if err != nil {
				c.err = err
				return
			}
			if len(rest) > 0 {
				c.err = errors.New("internal error: unexpected trailing data in entry")
				return
			}
			if !yield(i, entry) {
				return
			}
		}
	}
}

// Entry returns a log entry by its index, and an inclusion proof in the tree.
//
// The provided tree should have been verified by the caller, for example using
// [Client.Checkpoint].
func (c *Client) Entry(ctx context.Context, tree tlog.Tree, index int64) (*LogEntry, tlog.RecordProof, error) {
	e, proof, err := c.c.Entry(ctx, tree, index)
	if err != nil {
		return nil, nil, err
	}
	entry, rest, err := ReadTileLeaf(e)
	if err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to parse log entry %d: %w", index, err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("sunlight: unexpected trailing data in entry %d", index)
	}
	if entry.LeafIndex != index {
		return nil, nil, fmt.Errorf("sunlight: log entry index %d does not match requested index %d", entry.LeafIndex, index)
	}
	return entry, proof, nil
}

// VerifyInclusion verifies that the given data is included in the tree
// at the given index, using the provided inclusion proof.
func (c *Client) VerifyInclusion(proof tlog.RecordProof, treeSize int64, leafHash tlog.Hash, index int64, rootHash tlog.Hash) error {
	return tlog.CheckRecord(proof, treeSize, leafHash, index, rootHash)
}

func libraryVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "filippo.io/sunlight" {
			if dep.Replace != nil {
				return dep.Version + "!"
			}
			return dep.Version
		}
	}
	return "unknown"
}
