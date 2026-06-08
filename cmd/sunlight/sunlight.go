// Command sunlight runs a general-purpose append-only log write-path server.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"filippo.io/keygen"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/heavyhitter"
	"filippo.io/sunlight/internal/keylog"
	"filippo.io/sunlight/internal/reused"
	"filippo.io/sunlight/internal/stdlog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen []string
	ACME   struct {
		Cache     string
		Hosts     []string
		Directory string
	}
	Checkpoints string
	ETagS3      struct {
		Region   string
		Bucket   string
		Endpoint string
	}
	DynamoDB struct {
		Region   string
		Table    string
		Endpoint string
	}
	Logs []LogConfig
}

type LogConfig struct {
	Name             string
	ShortName        string
	Inception        string
	Period           int
	HTTPHost         string
	HTTPPrefix       string
	SubmissionPrefix string
	MonitoringPrefix string
	Secret           string
	Seed             string
	Cache            string
	PoolSize         int
	S3Region         string
	S3Bucket         string
	S3Endpoint       string
	S3KeyPrefix      string
	LocalDirectory   string
	// EntityKeys maps entity IDs to base64-encoded Ed25519 public keys.
	EntityKeys map[string]string `yaml:"entity_keys,omitempty"`
	// EntityBLSKeys maps entity IDs to base64-encoded BLS public keys.
	EntityBLSKeys map[string]string `yaml:"entity_bls_keys,omitempty"`
	// PhaseManagerKey is a base64-encoded Ed25519 public key of the external
	// actor that orchestrates phase changes (setup → voting → tallying).
	PhaseManagerKey string `yaml:"phase_manager_key,omitempty"`
}

type logInfo struct {
	Name             string `json:"description"`
	ShortName        string `json:"friendly_name"`
	SubmissionPrefix string `json:"submission_url"`
	MonitoringPrefix string `json:"monitoring_url"`
	PoolSize         int    `json:"pool_size"`
	ID               string `json:"log_id"`
	PublicKeyPEM     string `json:"public_key_pem,omitempty"`
	PublicKeyDER     []byte `json:"public_key_der,omitempty"`
	PublicKeyBase64  string `json:"public_key_base64,omitempty"`
	Software         struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"log_software"`
}

//go:embed home.html
var homeHTML string
var homeTmpl = template.Must(template.New("home").Parse(homeHTML))

func main() {
	fs := flag.NewFlagSet("sunlight", flag.ExitOnError)
	configFlag := fs.String("c", "sunlight.yaml", "path to the config file")
	testCertFlag := fs.Bool("testcert", false, "use test certificate")
	fs.Parse(os.Args[1:])

	logger := slog.New(stdlog.Handler)

	go func() {
		ln, err := net.Listen("tcp", "localhost:")
		if err != nil {
			logger.Error("failed to start debug server", "err", err)
		} else {
			logger.Info("debug server listening", "addr", ln.Addr())
			err := http.Serve(ln, nil)
			logger.Error("debug server exited", "err", err)
		}
	}()

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(stdlog.Handler.WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	}))
	sunlightMetrics := prometheus.WrapRegistererWithPrefix("sunlight_", metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	serveGroup, ctx := errgroup.WithContext(ctx)

	var db ctlog.LockBackend
	switch {
	case c.Checkpoints != "" && c.DynamoDB.Table != "" ||
		c.Checkpoints != "" && c.ETagS3.Bucket != "" ||
		c.DynamoDB.Table != "" && c.ETagS3.Bucket != "":
		fatalError(logger, "only one of Checkpoints, DynamoDB, or ETagS3 can be set")

	case c.Checkpoints != "":
		b, err := ctlog.NewSQLiteBackend(ctx, c.Checkpoints, logger)
		if err != nil {
			fatalError(logger, "failed to create SQLite backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.DynamoDB.Table != "":
		b, err := ctlog.NewDynamoDBBackend(ctx,
			c.DynamoDB.Region, c.DynamoDB.Table, c.DynamoDB.Endpoint, logger)
		if err != nil {
			fatalError(logger, "failed to create DynamoDB backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.ETagS3.Bucket != "":
		b, err := ctlog.NewETagBackend(ctx,
			c.ETagS3.Region, c.ETagS3.Bucket, c.ETagS3.Endpoint, logger)
		if err != nil {
			fatalError(logger, "failed to create ETag S3 backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	default:
		fatalError(logger, "neither Checkpoints nor DynamoDB are set")
	}

	sequencerGroup, sequencerContext := errgroup.WithContext(ctx)

	var logsMu sync.RWMutex
	logs := make(map[string]logInfo)
	homeLogsInfo := func() []logInfo {
		logsMu.RLock()
		defer logsMu.RUnlock()
		return slices.SortedFunc(maps.Values(logs), func(a, b logInfo) int {
			return strings.Compare(a.ShortName, b.ShortName)
		})
	}
	logInfoForShortName := func(shortName string) (logInfo, bool) {
		logsMu.RLock()
		defer logsMu.RUnlock()
		li, ok := logs[shortName]
		return li, ok
	}
	setLogInfo := func(shortName string, li logInfo) {
		logsMu.Lock()
		defer logsMu.Unlock()
		logs[shortName] = li
	}

	type witnessInfo struct{}
	homeWitnessInfo := func() witnessInfo { return witnessInfo{} }

	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if err := homeTmpl.Execute(w, struct {
			Logs    []logInfo
			Witness witnessInfo
		}{
			Logs:    homeLogsInfo(),
			Witness: homeWitnessInfo(),
		}); err != nil {
			logger.Error("failed to execute homepage template", "err", err)
		}
	})

	var acmeHosts []string
	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))
		if _, ok := logInfoForShortName(lc.ShortName); ok {
			fatalError(logger, "duplicate log short name")
		}

		var b ctlog.Backend
	switch {
		case lc.S3Bucket != "" && lc.LocalDirectory != "":
			fatalError(logger, "only one of S3Bucket or LocalDirectory can be set")
		case lc.S3Bucket != "":
			b, err = ctlog.NewS3Backend(ctx, lc.S3Region, lc.S3Bucket, lc.S3Endpoint, lc.S3KeyPrefix, logger)
			if err != nil {
				fatalError(logger, "failed to create backend", "err", err)
			}
		case lc.LocalDirectory != "":
			b, err = ctlog.NewLocalBackend(ctx, lc.LocalDirectory, logger)
			if err != nil {
				fatalError(logger, "failed to create backend", "err", err)
			}
		default:
			fatalError(logger, "neither S3Bucket nor LocalDirectory are set")
		}

		if lc.Secret == "" && lc.Seed != "" {
			logger.Warn("using deprecated Seed field, use Secret instead")
			lc.Secret = lc.Seed
		}
		seed, err := os.ReadFile(lc.Secret)
		if err != nil {
			fatalError(logger, "failed to load seed", "err", err)
		}
		if len(seed) != 32 {
			fatalError(logger, "seed file must be exactly 32 bytes")
		}

		ecdsaSecret := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("ECDSA P-256 log key")), ecdsaSecret); err != nil {
			fatalError(logger, "failed to derive ECDSA secret", "err", err)
		}
		k, err := keygen.ECDSA(elliptic.P256(), ecdsaSecret)
		if err != nil {
			fatalError(logger, "failed to generate ECDSA key", "err", err)
		}

		lc.SubmissionPrefix = strings.TrimSuffix(lc.SubmissionPrefix, "/")
		lc.MonitoringPrefix = strings.TrimSuffix(lc.MonitoringPrefix, "/")
		prefix, err := url.Parse(lc.SubmissionPrefix)
		if err != nil {
			fatalError(logger, "failed to parse SubmissionPrefix", "err", err)
		}
		if prefix.Scheme != "https" {
			fatalError(logger, "SubmissionPrefix must be an https URL", "prefix", lc.SubmissionPrefix)
		}
		if prefix.Host == "" {
			fatalError(logger, "SubmissionPrefix must have a host", "prefix", lc.SubmissionPrefix)
		}
		if lc.HTTPHost != "" && lc.HTTPHost != prefix.Host {
			fatalError(logger, "HTTPHost must match SubmissionPrefix host",
				"httpHost", lc.HTTPHost, "submissionPrefix", lc.SubmissionPrefix)
		}
		if lc.HTTPPrefix != "" && lc.HTTPPrefix != prefix.Path {
			fatalError(logger, "HTTPPrefix must match SubmissionPrefix path",
				"httpPrefix", lc.HTTPPrefix, "submissionPrefix", lc.SubmissionPrefix)
		}
		if lc.Name != "" && lc.Name != prefix.Host+prefix.Path {
			fatalError(logger, "Name must match SubmissionPrefix host and path",
				"name", lc.Name, "submissionPrefix", lc.SubmissionPrefix)
		}

		entityKeys := make(map[string]ed25519.PublicKey)
		for id, keyB64 := range lc.EntityKeys {
			keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
			if err != nil {
				fatalError(logger, "failed to decode entity key", "entity", id, "err", err)
			}
			if len(keyBytes) != ed25519.PublicKeySize {
				fatalError(logger, "invalid entity key length", "entity", id, "len", len(keyBytes))
			}
			entityKeys[id] = ed25519.PublicKey(keyBytes)
		}

		entityBLSKeys := make(map[string][]byte)
		for id, keyB64 := range lc.EntityBLSKeys {
			keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
			if err != nil {
				fatalError(logger, "failed to decode BLS entity key", "entity", id, "err", err)
			}
			entityBLSKeys[id] = keyBytes
		}

		var phaseManagerKey ed25519.PublicKey
		if lc.PhaseManagerKey != "" {
			keyBytes, err := base64.StdEncoding.DecodeString(lc.PhaseManagerKey)
			if err != nil {
				fatalError(logger, "failed to decode phase_manager key", "err", err)
			}
			if len(keyBytes) != ed25519.PublicKeySize {
				fatalError(logger, "invalid phase_manager key length", "len", len(keyBytes))
			}
			phaseManagerKey = ed25519.PublicKey(keyBytes)
		}

		cc := &ctlog.Config{
			Name:            prefix.Host + prefix.Path,
			Key:             k,
			Cache:           lc.Cache,
			PoolSize:        lc.PoolSize,
			Backend:         b,
			Lock:            db,
			Log:             logger,
			EntityKeys:      entityKeys,
			EntityBLSKeys:   entityBLSKeys,
			PhaseManagerKey: phaseManagerKey,
		}

		if time.Now().Format(time.DateOnly) == lc.Inception {
			logger.Info("today is the Inception date, creating log")
			if err := ctlog.CreateLog(ctx, cc); err == ctlog.ErrLogExists {
				logger.Info("log exists")
			} else if err != nil {
				fatalError(logger, "failed to create log", "err", err)
			}
		}

		l, err := ctlog.LoadLog(ctx, cc)
		if errors.Is(err, ctlog.ErrLogNotFound) {
			fatalError(logger, "log not found, but today is not the Inception date",
				"today", time.Now().Format(time.DateOnly), "inception", lc.Inception)
		} else if err != nil {
			fatalError(logger, "failed to load log", "err", err)
		}
		defer l.CloseCache()

		if err := updateMetadata(ctx, setLogInfo, lc, cc); err != nil {
			fatalError(logger, "failed to update log metadata", "err", err)
		}
		period := 1 * time.Second
		if lc.Period > 0 {
			period = time.Duration(lc.Period) * time.Millisecond
		}
		sequencerGroup.Go(func() error {
			return l.RunSequencer(sequencerContext, period)
		})

		mux.Handle(prefix.Host+prefix.Path+"/", http.StripPrefix(prefix.Path, l.Handler()))

		acmeHosts = append(acmeHosts, prefix.Hostname())

		prometheus.WrapRegistererWith(prometheus.Labels{"log": lc.ShortName}, sunlightMetrics).
			MustRegister(l.Metrics()...)

		mux.HandleFunc(prefix.Host+prefix.Path+"/log.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			li, _ := logInfoForShortName(lc.ShortName)
			e := json.NewEncoder(w)
			e.SetIndent("", "    ")
			e.Encode(li)
		})
	}

	handler := reused.NewHandler(mux)
	handler = heavyhitter.NewHandler(handler)
	s := &http.Server{
		Handler:      handler,
		ConnContext:  reused.ConnContext,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog:     stdlog.HTTPErrorLog,
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("sunlight.pem", "sunlight-key.pem")
		if err != nil {
			fatalError(logger, "failed to load test cert", "err", err)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else if c.ACME.Cache != "" {
		acmeHosts = append(acmeHosts, c.ACME.Hosts...)
		m := &autocert.Manager{
			Cache:      autocert.DirCache(c.ACME.Cache),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeHosts...),
			Client: &acme.Client{
				DirectoryURL: c.ACME.Directory,
				UserAgent:    "filippo.io/sunlight",
			},
		}
		s.TLSConfig = m.TLSConfig()
	} else {
		s.Handler = h2c.NewHandler(s.Handler, &http2.Server{})
	}

	if s.TLSConfig != nil {
		s.TLSConfig.KeyLogWriter = keylog.Writer
	}

	if len(c.Listen) == 0 {
		fatalError(logger, "no Listen addresses specified")
	}
	for _, addr := range c.Listen {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fatalError(logger, "failed to listen", "addr", addr, "err", err)
		}
		serveGroup.Go(func() error {
			if s.TLSConfig != nil {
				return s.ServeTLS(l, "", "")
			}
			return s.Serve(l)
		})
	}

	if err := sequencerGroup.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sequencer error", "err", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", "err", err)
	}

	if err := serveGroup.Wait(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve error", "err", err)
	}

	os.Exit(1)
}

func updateMetadata(ctx context.Context, setLogInfo func(string, logInfo), lc LogConfig, cc *ctlog.Config) error {
	pkix, err := x509.MarshalPKIXPublicKey(&cc.Key.PublicKey)
	if err != nil {
		return err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
	logID := sha256.Sum256(pkix)
	log := logInfo{
		Name:             cc.Name,
		ShortName:        lc.ShortName,
		ID:               base64.StdEncoding.EncodeToString(logID[:]),
		SubmissionPrefix: lc.SubmissionPrefix + "/",
		MonitoringPrefix: lc.MonitoringPrefix + "/",
		PoolSize:         lc.PoolSize,
		PublicKeyPEM:     string(pemKey),
		PublicKeyDER:     pkix,
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(pkix),
	}
	info, _ := debug.ReadBuildInfo()
	log.Software.Name = info.Main.Path
	log.Software.Version = info.Main.Version

	setLogInfo(lc.ShortName, log)

	j, err := json.MarshalIndent(log, "", "    ")
	if err != nil {
		return err
	}
	return cc.Backend.Upload(ctx, "log.json", j, &ctlog.UploadOptions{ContentType: "application/json"})
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
