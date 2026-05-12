package sunlight

import (
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

const TileHeight = 8
const TileWidth = 1 << TileHeight

// TilePath returns a tile coordinate path describing t, according to
// c2sp.org/static-st-api. It differs from [tlog.Tile.Path] in that it doesn't
// include an explicit tile height. It also supports names tiles at level -2.
//
// If t.Height is not TileHeight, TilePath panics.
func TilePath(t tlog.Tile) string {
	if t.H != TileHeight {
		panic(fmt.Sprintf("unexpected tile height %d", t.H))
	}
	if t.L == -2 {
		t.L = -1
		return "tile/names/" + strings.TrimPrefix(t.Path(), "tile/8/data/")
	}
	return "tile/" + strings.TrimPrefix(t.Path(), "tile/8/")
}

// ParseTilePath parses a tile coordinate path according to c2sp.org/static-st-api.
// It differs from [tlog.ParseTilePath] in that it doesn't include an explicit
// tile height. It also supports names tiles at level -2.
func ParseTilePath(path string) (tlog.Tile, error) {
	if rest, ok := strings.CutPrefix(path, "tile/names/"); ok {
		t, err := tlog.ParseTilePath("tile/8/data/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		t.L = -2
		return t, nil
	}
	if rest, ok := strings.CutPrefix(path, "tile/"); ok {
		t, err := tlog.ParseTilePath("tile/8/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
}

// LogEntry represents a generic entry in the append-only log.
// This is a simplified version that stores arbitrary data as a blob.
type LogEntry struct {
	// Data is the arbitrary content of the log entry.
	// It must be at most 2^24-1 bytes long.
	Data []byte

	// LeafIndex is the zero-based index of the leaf in the log.
	// It must be between 0 and 2^40-1.
	LeafIndex int64

	// Timestamp is when the entry was added to the log (Unix milliseconds).
	Timestamp int64

	// RFC6962ArchivalLeaf is kept for backward compatibility with existing data.
	// For new entries, this should always be false.
	RFC6962ArchivalLeaf bool
}

// MerkleTreeLeaf returns a simple Merkle tree leaf hash.
// This is a simplified version that hashes the data directly.
func (e *LogEntry) MerkleTreeLeaf() []byte {
	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* version = v1 */)
	b.AddUint8(0 /* leaf_type = timestamped_entry */)
	b.AddUint64(uint64(e.Timestamp))
	b.AddUint16(0 /* entry_type = generic blob */)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Data)
	})
	addExtensions(b, e)
	return b.BytesOrPanic()
}

// ReadTileLeaf reads a LogEntry from a data tile, and returns the remaining
// data in the tile.
func ReadTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
	e, rest, err = readTileLeaf(tile)
	if err != nil {
		return nil, rest, err
	}
	if e.RFC6962ArchivalLeaf {
		return nil, rest, fmt.Errorf("leaf is missing leaf index extension")
	}
	return e, rest, nil
}

// ReadTileLeafMaybeArchival reads a LogEntry from a data tile, and returns the
// remaining data in the tile.
//
// If the leaf is missing the leaf index extension, the returned LogEntry has
// RFC6962ArchivalLeaf set to true, and LeafIndex set to zero.
func ReadTileLeafMaybeArchival(tile []byte) (e *LogEntry, rest []byte, err error) {
	return readTileLeaf(tile)
}

func readTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
	e = &LogEntry{}
	s := cryptobyte.String(tile)
	var timestamp uint64
	var entryType uint16
	var extensions cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, fmt.Errorf("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	
	// Support both generic blob (type 0) and legacy x509_entry (type 0 was reused)
	// We read the data field regardless
	if entryType != 0 && entryType != 1 {
		return nil, s, fmt.Errorf("invalid data tile: unknown type %d", entryType)
	}
	
	if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Data)) ||
		!s.ReadUint16LengthPrefixed(&extensions) {
		return nil, s, fmt.Errorf("invalid data tile: failed to read data")
	}
	
	// Skip legacy precertificate field if present (for backward compatibility)
	if entryType == 1 {
		var dummy cryptobyte.String
		s.ReadUint24LengthPrefixed(&dummy)
	}
	
	if extensions.Empty() {
		e.RFC6962ArchivalLeaf = true
	} else {
		var extensionType uint8
		var extensionData cryptobyte.String
		if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
			!extensions.ReadUint16LengthPrefixed(&extensionData) ||
			!readUint40(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
			!extensions.Empty() {
			return nil, s, fmt.Errorf("invalid data tile extensions")
		}
	}
	
	return e, s, nil
}

// AppendTileLeaf appends a LogEntry to a data tile.
func AppendTileLeaf(t []byte, e *LogEntry) []byte {
	b := cryptobyte.NewBuilder(t)
	b.AddUint64(uint64(e.Timestamp))
	b.AddUint16(0 /* entry_type = generic blob */)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Data)
	})
	addExtensions(b, e)
	return b.BytesOrPanic()
}

func addExtensions(b *cryptobyte.Builder, e *LogEntry) {
	if e.RFC6962ArchivalLeaf {
		b.AddUint16(0)
		return
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		ext, err := MarshalExtensions(Extensions{LeafIndex: e.LeafIndex})
		if err != nil {
			b.SetError(err)
			return
		}
		b.AddBytes(ext)
	})
}


