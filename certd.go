package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// set by goreleaser via -X ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var errInstallationFailed = errors.New("installation failed")
var errExternalIPCheckFailed = errors.New("unable to check external IP using any provider")

// algorithm represents a supported key algorithm.
type algorithm string

const (
	algorithmRSA     algorithm = "rsa"
	algorithmECDSA   algorithm = "ecdsa"
	algorithmEd25519 algorithm = "ed25519"
)

// certPaths holds the file paths for a single algorithm's cert and key.
type certPaths struct {
	cert   string // e.g. /etc/configd/tls/server_rsa.crt
	key    string // e.g. /etc/configd/tls/server_rsa.key
	notify string // e.g. /run/certd/cert-updated-rsa
}

// certState holds the last known state for a single algorithm's certificate.
type certState struct {
	hostname    string
	internalIPs []string
	externalIP  string
}

// config holds all runtime configuration for the daemon.
type config struct {
	algorithms   []algorithm
	lifetime     time.Duration
	certDir      string
	notifyDir    string
	internalIP   bool
	externalIP   bool
	pollInterval time.Duration
	maxRetries   int
	install      bool
	version      bool
}

const (
	defaultCertDir      = "/var/lib/certd"
	defaultNotifyDir    = "/run/certd"
	defaultPollInterval = 1 * time.Hour
	defaultMaxRetries   = 5
	defaultLifetime     = 8760 * time.Hour // 1 year
	renewThreshold      = 1.0 / 3.0        // renew when less than 1/3 of lifetime remains
)

var externalIPProviders = []string{
	"https://ipv4.icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://ifconfig.io/ip",
}

//go:embed files/**
var embeddedFiles embed.FS

func main() {
	cfg := parseConfig()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if cfg.install {
		if err := installEmbeddedFiles(logger); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		logger.Info("installation completed successfully")
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config, logger *slog.Logger) error {
	algNames := make([]string, len(cfg.algorithms))
	for i, a := range cfg.algorithms {
		algNames[i] = string(a)
	}
	logger.Info("certd starting",
		"algorithms", strings.Join(algNames, ","),
		"lifetime", cfg.lifetime,
		"certDir", cfg.certDir,
		"notifyDir", cfg.notifyDir,
		"internalIP", cfg.internalIP,
		"externalIP", cfg.externalIP,
		"pollInterval", cfg.pollInterval,
		"maxRetries", cfg.maxRetries,
	)

	// Initialise per-algorithm state
	states := make(map[algorithm]*certState, len(cfg.algorithms))
	for _, alg := range cfg.algorithms {
		states[alg] = &certState{}
	}

	// Run an immediate check before entering the poll loop
	if err := checkAll(ctx, cfg, logger, states); err != nil {
		return err
	}

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return ctx.Err()
		case <-ticker.C:
			if err := checkAll(ctx, cfg, logger, states); err != nil {
				return err
			}
		}
	}
}

// checkAll runs a poll cycle for every enabled algorithm independently.
func checkAll(ctx context.Context, cfg *config, logger *slog.Logger, states map[algorithm]*certState) error {
	// Gather host info once — shared across all algorithms in this cycle
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %w", err)
	}

	var internalIPs []string
	if cfg.internalIP {
		internalIPs, err = getInternalIPs()
		if err != nil {
			logger.Warn("failed to get internal IPs, continuing without them", "err", err)
		}
	}

	var externalIP string
	if cfg.externalIP {
		// Use the first algorithm's state for the last-known external IP fallback
		lastKnown := states[cfg.algorithms[0]].externalIP
		externalIP, err = getExternalIPWithRetry(ctx, cfg.maxRetries, logger)
		if err != nil {
			logger.Warn("could not determine external IP, using last known value",
				"lastKnown", lastKnown,
				"err", err,
			)
			externalIP = lastKnown
		}
	}

	// Process each algorithm independently — errors are logged but don't stop others
	for _, alg := range cfg.algorithms {
		paths := certPathsForAlgorithm(cfg, alg)
		st := states[alg]
		algLogger := logger.With("algorithm", alg)

		if err := checkOne(algLogger, cfg, alg, paths, st, hostname, internalIPs, externalIP); err != nil {
			algLogger.Error("failed to process certificate, will retry next poll", "err", err)
		}
	}

	return nil
}

// checkOne performs a single check-and-issue cycle for one algorithm.
func checkOne(
	logger *slog.Logger,
	cfg *config,
	alg algorithm,
	paths certPaths,
	st *certState,
	hostname string,
	internalIPs []string,
	externalIP string,
) error {
	// Case 1: cert or key missing
	if !fileExists(paths.cert) || !fileExists(paths.key) {
		logger.Info("certificate not found, issuing")
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// Parse existing cert
	cert, err := loadCert(paths.cert)
	if err != nil {
		logger.Warn("failed to parse existing certificate, re-issuing", "err", err)
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// Case 2: hostname changed
	if st.hostname != "" && hostname != st.hostname {
		logger.Info("hostname changed, re-issuing", "old", st.hostname, "new", hostname)
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// Case 3: internal IPs changed
	if cfg.internalIP && st.hostname != "" && !stringSlicesEqual(internalIPs, st.internalIPs) {
		logger.Info("internal IPs changed, re-issuing", "old", st.internalIPs, "new", internalIPs)
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// Case 4: external IP changed
	if cfg.externalIP && st.externalIP != "" && externalIP != "" && externalIP != st.externalIP {
		logger.Info("external IP changed, re-issuing", "old", st.externalIP, "new", externalIP)
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// Case 5: renewal due
	if needsRenewal(cert, renewThreshold) {
		logger.Info("certificate due for renewal",
			"notAfter", cert.NotAfter,
			"remaining", time.Until(cert.NotAfter).Round(time.Hour),
		)
		if err := issueCert(logger, cfg, alg, paths, hostname, internalIPs, externalIP); err != nil {
			return err
		}
		updateState(st, hostname, internalIPs, externalIP)
		return touchNotifyFile(logger, paths.notify)
	}

	// No action needed — update state on first successful poll
	updateState(st, hostname, internalIPs, externalIP)
	logger.Info("certificate is valid, no action needed",
		"subject", cert.Subject.CommonName,
		"notAfter", cert.NotAfter,
		"remaining", time.Until(cert.NotAfter).Round(time.Hour),
	)
	return nil
}

// certPathsForAlgorithm returns the predetermined file paths for a given algorithm.
func certPathsForAlgorithm(cfg *config, alg algorithm) certPaths {
	return certPaths{
		cert:   filepath.Join(cfg.certDir, fmt.Sprintf("server_%s.crt", alg)),
		key:    filepath.Join(cfg.certDir, fmt.Sprintf("server_%s.key", alg)),
		notify: filepath.Join(cfg.notifyDir, fmt.Sprintf("cert-updated-%s", alg)),
	}
}

// issueCert generates a new private key and self-signed certificate for one algorithm.
func issueCert(
	logger *slog.Logger,
	cfg *config,
	alg algorithm,
	paths certPaths,
	hostname string,
	internalIPs []string,
	externalIP string,
) error {
	logger.Info("issuing certificate",
		"hostname", hostname,
		"internalIPs", internalIPs,
		"externalIP", externalIP,
		"lifetime", cfg.lifetime,
	)

	certDER, keyPEM, err := generateCert(alg, cfg, hostname, internalIPs, externalIP)
	if err != nil {
		return fmt.Errorf("generating certificate: %w", err)
	}

	if err := os.MkdirAll(cfg.certDir, 0750); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(paths.cert, certPEM, 0640); err != nil { //#nosec G306
		return fmt.Errorf("writing cert file: %w", err)
	}
	if err := os.WriteFile(paths.key, keyPEM, 0640); err != nil { //#nosec G306
		return fmt.Errorf("writing key file: %w", err)
	}

	logger.Info("certificate issued successfully", "cert", paths.cert, "key", paths.key)
	return nil
}

// generateCert builds the x509 template and dispatches to the right key generator.
func generateCert(alg algorithm, cfg *config, hostname string, internalIPs []string, externalIP string) (certDER []byte, keyPEM []byte, err error) {
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	for _, ip := range internalIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			ipAddresses = append(ipAddresses, parsed)
		}
	}
	if externalIP != "" {
		if parsed := net.ParseIP(externalIP); parsed != nil {
			ipAddresses = append(ipAddresses, parsed)
		}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	notBefore := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname, "localhost"},
		IPAddresses:  ipAddresses,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(cfg.lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	switch alg {
	case algorithmRSA:
		return generateRSA(template)
	case algorithmECDSA:
		return generateECDSA(template)
	case algorithmEd25519:
		return generateEd25519(template)
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %q", alg)
	}
}

func generateRSA(template *x509.Certificate) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("generating RSA key: %w", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating RSA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling RSA key: %w", err)
	}
	return certDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func generateECDSA(template *x509.Certificate) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating ECDSA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling ECDSA key: %w", err)
	}
	return certDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func generateEd25519(template *x509.Certificate) ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("creating Ed25519 certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling Ed25519 key: %w", err)
	}
	return certDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// getInternalIPs returns all non-loopback IPv4 addresses on the host.
func getInternalIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips, nil
}

// getExternalIPWithRetry fetches the external IP with exponential backoff.
func getExternalIPWithRetry(ctx context.Context, maxRetries int, logger *slog.Logger) (string, error) {
	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		ip, err := getExternalIP(ctx, logger)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		logger.Warn("failed to get external IP, will retry",
			"attempt", attempt,
			"maxRetries", maxRetries,
			"backoff", backoff,
			"err", err,
		)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return "", fmt.Errorf("all %d attempts failed, last error: %w", maxRetries, lastErr)
}

// getExternalIP tries each provider in order, returning the first valid IPv4 response.
func getExternalIP(ctx context.Context, logger *slog.Logger) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, provider := range externalIPProviders {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider, nil)
		if err != nil {
			logger.Warn("external IP provider request creation failed", "provider", provider, "err", err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("external IP provider request failed", "provider", provider, "err", err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		closeErr := resp.Body.Close()
		if err != nil {
			logger.Warn("external IP provider response read failed", "provider", provider, "err", err)
			if closeErr != nil {
				logger.Warn("external IP provider response body close failed", "provider", provider, "err", closeErr)
			}
			continue
		}
		if closeErr != nil {
			logger.Warn("external IP provider response body close failed", "provider", provider, "err", closeErr)
			continue
		}
		ip := strings.TrimSpace(string(body))
		if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
			logger.Warn("external IP provider returned invalid IPv4", "provider", provider, "response", ip)
			continue
		}
		return ip, nil
	}
	return "", errExternalIPCheckFailed
}

// needsRenewal returns true when less than threshold fraction of lifetime remains.
func needsRenewal(cert *x509.Certificate, threshold float64) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	remaining := time.Until(cert.NotAfter)
	return remaining < time.Duration(float64(lifetime)*threshold)
}

// loadCert reads and parses the first certificate from a PEM file.
func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// touchNotifyFile creates or updates the mtime of the per-algorithm notification file.
func touchNotifyFile(logger *slog.Logger, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("creating notify dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("touching notify file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	logger.Info("touched notify file", "path", path)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func updateState(st *certState, hostname string, internalIPs []string, externalIP string) {
	st.hostname = hostname
	st.internalIPs = internalIPs
	st.externalIP = externalIP
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func printVersion() {
	fmt.Printf("certd %s (commit: %s, built: %s, %s)\n",
		version, commit, date, runtime.Version())
}

//nolint:gosec // install mode writes intentional system paths and file modes from embedded, trusted assets.
func installEmbeddedFiles(logger *slog.Logger) error {
	if os.Geteuid() != 0 {
		logger.Error("installation requires root privileges")
		return errInstallationFailed
	}

	contentFS, err := fs.Sub(embeddedFiles, "files")
	if err != nil {
		logger.Error("failed to prepare embedded files", "err", err)
		return errInstallationFailed
	}

	errorCount := 0

	execPath, err := os.Executable()
	if err != nil {
		errorCount++
		logger.Error("failed to determine executable path", "err", err)
	} else {
		if resolvedExecPath, evalErr := filepath.EvalSymlinks(execPath); evalErr == nil {
			execPath = resolvedExecPath
		}
		const binDir = "/usr/local/bin"
		const binPath = "/usr/local/bin/certd"
		resolvedBinPath := binPath
		if rp, evalErr := filepath.EvalSymlinks(binPath); evalErr == nil {
			resolvedBinPath = rp
		}

		// #nosec G301 -- install mode intentionally creates world-readable system directories.
		if err := os.MkdirAll(binDir, 0755); err != nil {
			errorCount++
			logger.Error("failed to create binary directory", "path", binDir, "err", err)
		} else if execPath == resolvedBinPath {
			logger.Info("source binary already matches destination, skipping binary copy", "path", binPath)
		} else {
			src, err := os.Open(execPath)
			if err != nil {
				errorCount++
				logger.Error("failed to open source binary", "path", execPath, "err", err)
			} else {
				// #nosec G302 -- installed binary should be executable by all users.
				dst, err := os.OpenFile(binPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					errorCount++
					logger.Error("failed to open destination binary", "path", binPath, "err", err)
					if closeErr := src.Close(); closeErr != nil {
						errorCount++
						logger.Error("failed to close source binary", "path", execPath, "err", closeErr)
					}
				} else {
					if _, err := io.Copy(dst, src); err != nil {
						errorCount++
						logger.Error("failed to copy binary", "source", execPath, "target", binPath, "err", err)
					} else {
						logger.Info("installed binary", "source", execPath, "target", binPath)
					}
					if closeErr := src.Close(); closeErr != nil {
						errorCount++
						logger.Error("failed to close source binary", "path", execPath, "err", closeErr)
					}
					if closeErr := dst.Close(); closeErr != nil {
						errorCount++
						logger.Error("failed to close destination binary", "path", binPath, "err", closeErr)
					}
				}
			}
		}
	}

	walkErr := fs.WalkDir(contentFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errorCount++
			logger.Error("failed to access embedded entry", "path", path, "err", err)
			return nil
		}
		if path == "." {
			return nil
		}

		targetPath := string(os.PathSeparator) + filepath.Clean(path)

		if d.IsDir() {
			// #nosec G301 -- install mode intentionally creates world-readable system directories.
			// #nosec G122 -- source paths come from compile-time embedded assets, not user input.
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				errorCount++
				logger.Error("failed to create directory", "path", targetPath, "err", err)
			}
			return nil
		}

		// #nosec G301 -- install mode intentionally creates world-readable system directories.
		// #nosec G122 -- source paths come from compile-time embedded assets, not user input.
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			errorCount++
			logger.Error("failed to create parent directory", "path", filepath.Dir(targetPath), "err", err)
			return nil
		}

		src, err := contentFS.Open(path)
		if err != nil {
			errorCount++
			logger.Error("failed to read embedded file", "path", path, "err", err)
			return nil
		}

		// #nosec G302 -- installed service/config files are expected to be world-readable.
		// #nosec G122 -- source paths come from compile-time embedded assets, not user input.
		f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			errorCount++
			logger.Error("failed to open destination file", "path", targetPath, "err", err)
			if closeErr := src.Close(); closeErr != nil {
				errorCount++
				logger.Error("failed to close embedded file", "path", path, "err", closeErr)
			}
			return nil
		}
		if _, err := io.Copy(f, src); err != nil {
			errorCount++
			logger.Error("failed to copy file content", "path", targetPath, "err", err)
			if closeErr := src.Close(); closeErr != nil {
				errorCount++
				logger.Error("failed to close embedded file", "path", path, "err", closeErr)
			}
			if closeErr := f.Close(); closeErr != nil {
				errorCount++
				logger.Error("failed to close destination file", "path", targetPath, "err", closeErr)
			}
			return nil
		}
		if err := src.Close(); err != nil {
			errorCount++
			logger.Error("failed to close embedded file", "path", path, "err", err)
			if closeErr := f.Close(); closeErr != nil {
				errorCount++
				logger.Error("failed to close destination file", "path", targetPath, "err", closeErr)
			}
			return nil
		}
		if err := f.Close(); err != nil {
			errorCount++
			logger.Error("failed to close destination file", "path", targetPath, "err", err)
			return nil
		}

		logger.Info("installed file", "source", path, "target", targetPath)
		return nil
	})
	if walkErr != nil {
		errorCount++
		logger.Error("failed to walk embedded files", "err", walkErr)
	}

	if errorCount > 0 {
		logger.Error("installation completed with errors", "errorCount", errorCount)
		return errInstallationFailed
	}
	return nil
}

// parseConfig reads CLI flags and env vars; CLI flags take precedence over env vars.
func parseConfig() *config {
	// Need a bootstrap logger for duration parse warnings before the main logger is set up
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	var useRSA, useECDSA, useEd25519 bool

	flag.BoolVar(&useRSA, "rsa", envBoolOrDefault("CERTD_RSA", false),
		"Generate and manage RSA 4096 certificate (env: CERTD_RSA)")
	flag.BoolVar(&useECDSA, "ecdsa", envBoolOrDefault("CERTD_ECDSA", false),
		"Generate and manage ECDSA P-256 certificate (env: CERTD_ECDSA)")
	flag.BoolVar(&useEd25519, "ed25519", envBoolOrDefault("CERTD_ED25519", false),
		"Generate and manage Ed25519 certificate (env: CERTD_ED25519)")

	cfg := &config{}

	// Duration flags: parse env var default through parseDuration, then accept CLI override
	lifetimeEnv := envDurationOrDefault("CERTD_LIFETIME", defaultLifetime, logger)
	pollIntervalEnv := envDurationOrDefault("CERTD_POLL_INTERVAL", defaultPollInterval, logger)

	var lifetimeStr, pollIntervalStr string
	flag.StringVar(&lifetimeStr, "lifetime", "",
		"Certificate lifetime, e.g. 1y, 90d, 8760h (env: CERTD_LIFETIME)")
	flag.StringVar(&pollIntervalStr, "poll-interval", "",
		"How often to check for changes, e.g. 1d, 12h (env: CERTD_POLL_INTERVAL)")

	flag.StringVar(&cfg.certDir, "cert-dir", envOrDefault("CERTD_CERT_DIR", defaultCertDir),
		"Directory for certificate and key files (env: CERTD_CERT_DIR)")
	flag.StringVar(&cfg.notifyDir, "notify-dir", envOrDefault("CERTD_NOTIFY_DIR", defaultNotifyDir),
		"Directory for per-algorithm notification files (env: CERTD_NOTIFY_DIR)")
	flag.BoolVar(&cfg.internalIP, "internal-ip", envBoolOrDefault("CERTD_INTERNAL_IP", false),
		"Include internal IPs in certificate SANs (env: CERTD_INTERNAL_IP)")
	flag.BoolVar(&cfg.externalIP, "external-ip", envBoolOrDefault("CERTD_EXTERNAL_IP", false),
		"Include external IP in certificate SANs (env: CERTD_EXTERNAL_IP)")
	flag.IntVar(&cfg.maxRetries, "max-retries", envIntOrDefault("CERTD_MAX_RETRIES", defaultMaxRetries),
		"Max retries for external IP detection (env: CERTD_MAX_RETRIES)")
	flag.BoolVar(&cfg.install, "install", false, "Install embedded files to host paths and exit (requires root)")
	flag.BoolVar(&cfg.version, "version", false, "print version and exit")

	flag.Parse()

	if cfg.version {
		printVersion()
		os.Exit(0)
	}

	// Resolve lifetime: CLI flag overrides env var
	cfg.lifetime = lifetimeEnv
	if lifetimeStr != "" {
		d, err := parseDuration(lifetimeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -lifetime value %q: %v\n", lifetimeStr, err)
			os.Exit(1)
		}
		cfg.lifetime = d
	}

	// Resolve poll-interval: CLI flag overrides env var
	cfg.pollInterval = pollIntervalEnv
	if pollIntervalStr != "" {
		d, err := parseDuration(pollIntervalStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -poll-interval value %q: %v\n", pollIntervalStr, err)
			os.Exit(1)
		}
		cfg.pollInterval = d
	}

	// Build algorithm list — default to ECDSA if none specified
	if useRSA {
		cfg.algorithms = append(cfg.algorithms, algorithmRSA)
	}
	if useECDSA {
		cfg.algorithms = append(cfg.algorithms, algorithmECDSA)
	}
	if useEd25519 {
		cfg.algorithms = append(cfg.algorithms, algorithmEd25519)
	}
	if len(cfg.algorithms) == 0 {
		cfg.algorithms = []algorithm{algorithmECDSA}
	}

	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationOrDefault(key string, def time.Duration, logger *slog.Logger) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := parseDuration(v)
		if err != nil {
			logger.Warn("invalid duration in env var, using default",
				"key", key,
				"value", v,
				"default", def,
				"err", err,
			)
			return def
		}
		return d
	}
	return def
}

// extendedDurationRe matches a number followed by y, w, or d.
var extendedDurationRe = regexp.MustCompile(`(\d+)(y|w|d)`)

// parseDuration extends Go's time.ParseDuration with support for:
//
//	y = 365 * 24h
//	w = 7 * 24h
//	d = 24h
//
// Units can be combined: "1y30d", "2w3d12h", "90d".
func parseDuration(s string) (time.Duration, error) {
	var total time.Duration
	remainder := extendedDurationRe.ReplaceAllStringFunc(s, func(match string) string {
		m := extendedDurationRe.FindStringSubmatch(match)
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "y":
			total += time.Duration(n) * 8760 * time.Hour
		case "w":
			total += time.Duration(n) * 168 * time.Hour
		case "d":
			total += time.Duration(n) * 24 * time.Hour
		}
		return ""
	})
	if remainder != "" {
		d, err := time.ParseDuration(remainder)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		total += d
	}
	if total == 0 && s != "0" {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total, nil
}

func envBoolOrDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return strings.EqualFold(v, "true") || v == "1"
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i
		}
	}
	return def
}
