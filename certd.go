// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Krzysztof Ciepłucha

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
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
	"slices"
	"strconv"
	"strings"
	"sync"
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

// certStatus holds the last known status of a single algorithm's certificate,
// used by the HTTP health and metrics endpoints.
type certStatus struct {
	err       error // non-nil if last issue/check failed
	notBefore time.Time
	notAfter  time.Time
	subject   string
	dnsNames  []string
	ipAddrs   []string
	renewals  int64 // total number of times cert was issued/renewed
	errors    int64 // total number of failed issue attempts
}

// statusStore is a thread-safe store of per-algorithm certificate status.
type statusStore struct {
	mu       sync.RWMutex
	statuses map[algorithm]*certStatus
}

func newStatusStore(algorithms []algorithm) *statusStore {
	s := &statusStore{statuses: make(map[algorithm]*certStatus, len(algorithms))}
	for _, alg := range algorithms {
		s.statuses[alg] = &certStatus{}
	}
	return s
}

func (s *statusStore) setOK(alg algorithm, cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.statuses[alg]
	st.err = nil
	st.notBefore = cert.NotBefore
	st.notAfter = cert.NotAfter
	st.subject = cert.Subject.CommonName
	st.dnsNames = cert.DNSNames
	ipAddrs := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddrs[i] = ip.String()
	}
	st.ipAddrs = ipAddrs
}

func (s *statusStore) recordRenewal(alg algorithm) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[alg].renewals++
}

func (s *statusStore) recordError(alg algorithm, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.statuses[alg]
	st.err = err
	st.errors++
}

func (s *statusStore) snapshot() map[algorithm]certStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[algorithm]certStatus, len(s.statuses))
	for alg, st := range s.statuses {
		out[alg] = *st
	}
	return out
}

// certPaths holds the file paths for a single algorithm's cert and key.
type certPaths struct {
	cert   string // e.g. /var/lib/certd/tls/server_rsa.crt
	key    string // e.g. /var/lib/certd/tls/server_rsa.key
	notify string // e.g. /run/certd/cert-updated-rsa
}

// certState holds the last known state for a single algorithm's certificate.
type certState struct {
	hostname            string
	internalIPs         []string
	externalIP          string
	notificationPending bool
}

// addressDiscovery holds the result of one poll cycle's address discovery.
// The two sources are tracked separately: a failure in one must neither discard
// what the other established nor preserve what it disproved.
type addressDiscovery struct {
	internalIPs []string
	// internalComplete reports that internalIPs is authoritative — interface
	// enumeration succeeded, or internal addresses are disabled entirely.
	internalComplete bool
	externalIP       string
	// externalComplete reports that externalIP is authoritative — it was
	// detected, carried over from a last known value, or disabled entirely.
	externalComplete bool
}

// complete reports whether every enabled source produced an authoritative
// answer, so the resulting SAN set can be compared against a certificate.
func (d addressDiscovery) complete() bool {
	return d.internalComplete && d.externalComplete
}

// config holds all runtime configuration for the daemon.
type config struct {
	algorithms   []algorithm
	lifetime     time.Duration
	certDir      string
	notifyDir    string
	internalIP   bool
	interfaces   []string
	extraIPs     []net.IP
	extraDNS     []string
	externalIP   bool
	pollInterval time.Duration
	maxRetries   int
	httpAddr     string
	install      bool
	version      bool
}

const (
	defaultCertDir      = "/var/lib/certd"
	defaultNotifyDir    = "/run/certd"
	defaultPollInterval = 1 * time.Hour
	defaultMaxRetries   = 5
	defaultLifetime     = 8760 * time.Hour // 1 year
	defaultHTTPAddr     = "127.0.0.1:8484"

	// Every algorithm is off by default; parseConfig falls back to ECDSA when
	// none was selected. Named alongside the rest so the documented defaults
	// have a single source to be checked against.
	// Lower bounds for the two interval settings. certd re-issues by touching a
	// notification file, which restarts every dependent service, so rotating
	// faster than this costs far more than the shorter lifetime is worth.
	minLifetime     = 1 * time.Hour
	minPollInterval = 1 * time.Minute

	// Upper bounds. certd issues self-signed certificates with no revocation
	// path, so the lifetime is the whole compromise window; 25y is already far
	// beyond the life of the host it identifies. A poll interval above a day
	// stops certd doing the job it exists for, since a hostname or address
	// change goes unnoticed for that long. Each retry costs a flat 16s once the
	// backoff reaches its cap, so twenty attempts spend about four minutes
	// before giving up and leaving it to the next poll, which retries anyway
	// against a last known value kept in the meantime. Retries are separately
	// held against the poll interval, so this ceiling only binds where the
	// interval is long enough to afford it.
	maxLifetime     = 25 * 8760 * time.Hour
	maxPollInterval = 24 * time.Hour
	minRetries      = 1
	maxRetries      = 20

	// maxBackoff caps the delay between external IP attempts. Doubling without
	// a ceiling makes each extra retry cost as much as every one before it put
	// together, so the count buys exponential time rather than more attempts:
	// at twenty retries the final sleep alone runs for six days. Capped, the
	// same twenty retries cost four and a half minutes. The default of five
	// never reaches the cap, so its schedule is unchanged.
	maxBackoff = 16 * time.Second

	// interfacesAll selects every non-loopback interface, which is what certd
	// did before it learned to follow the default route. interfacesDefaultRoute
	// names the default behaviour, so a unit file can state which it relies on
	// rather than leaving the setting empty and implying it.
	interfacesAll          = "all"
	interfacesDefaultRoute = "default-route"

	// defaultRouteProbe is in TEST-NET-1 (RFC 5737), reserved for documentation
	// and never routed anywhere. Connecting a UDP socket to it transmits
	// nothing; it only asks the kernel which route, and so which source
	// address, the host would use to reach somewhere off-link.
	defaultRouteProbe = "192.0.2.1:9"

	defaultRSA        = false
	defaultECDSA      = false
	defaultEd25519    = false
	defaultInternalIP = false
	defaultExternalIP = false
	renewThreshold    = 1.0 / 3.0 // renew when less than 1/3 of lifetime remains
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
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

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
		"interfaces", interfaceSelectionText(cfg.interfaces),
		"extraSANs", strings.Join(append(ipAddressesToStrings(cfg.extraIPs), cfg.extraDNS...), ","),
		"externalIP", cfg.externalIP,
		"pollInterval", cfg.pollInterval,
		"maxRetries", cfg.maxRetries,
		"httpAddr", cfg.httpAddr,
	)

	store := newStatusStore(cfg.algorithms)
	startTime := time.Now()

	var httpServerErrors <-chan error

	// Bind the HTTP listener synchronously so configuration and address conflicts
	// fail startup instead of leaving the daemon running without its endpoints.
	if cfg.httpAddr != "" {
		srv := newHTTPServer(cfg, store, startTime, logger)
		var listenConfig net.ListenConfig
		listener, err := listenConfig.Listen(ctx, "tcp", cfg.httpAddr)
		if err != nil {
			return fmt.Errorf("binding HTTP server to %q: %w", cfg.httpAddr, err)
		}
		serverErrors := make(chan error, 1)
		httpServerErrors = serverErrors
		go func() {
			logger.Info("starting HTTP server", "addr", cfg.httpAddr)
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrors <- fmt.Errorf("serving HTTP: %w", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				logger.Warn("HTTP server shutdown error", "err", err)
			}
		}()
	}

	// Initialise per-algorithm state
	states := make(map[algorithm]*certState, len(cfg.algorithms))
	for _, alg := range cfg.algorithms {
		states[alg] = &certState{}
	}

	// Run an immediate check before entering the poll loop. Do not report
	// readiness until every enabled certificate has completed its first cycle.
	initialCheckOK, err := checkAll(ctx, cfg, logger, states, store)
	if err != nil {
		return err
	}
	if !initialCheckOK {
		return errors.New("initial certificate check failed")
	}
	select {
	case err := <-httpServerErrors:
		return err
	default:
	}
	if err := notifySystemdReady(); err != nil {
		return fmt.Errorf("notifying systemd of readiness: %w", err)
	}
	logger.Info("certd ready")

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return ctx.Err()
		case err := <-httpServerErrors:
			return err
		case <-ticker.C:
			if _, err := checkAll(ctx, cfg, logger, states, store); err != nil {
				return err
			}
		}
	}
}

func validateConfig(cfg *config) error {
	if len(cfg.algorithms) == 0 {
		return errors.New("at least one certificate algorithm must be enabled")
	}
	if cfg.lifetime < minLifetime || cfg.lifetime > maxLifetime {
		return fmt.Errorf("certificate lifetime must be between %s and %s, got %s",
			humanDuration(minLifetime), humanDuration(maxLifetime), humanDuration(cfg.lifetime))
	}
	if cfg.pollInterval < minPollInterval || cfg.pollInterval > maxPollInterval {
		return fmt.Errorf("poll interval must be between %s and %s, got %s",
			humanDuration(minPollInterval), humanDuration(maxPollInterval), humanDuration(cfg.pollInterval))
	}
	// Renewal only begins once less than renewThreshold of the lifetime remains,
	// and certd notices no sooner than the next poll, so a poll has to fall
	// inside that window. Otherwise the certificate expires before it is renewed
	// however generous the threshold looks.
	renewWindow := time.Duration(float64(cfg.lifetime) * renewThreshold)
	if cfg.pollInterval >= renewWindow {
		return fmt.Errorf(
			"poll interval %s is too long for a %s certificate lifetime: renewal begins with %s remaining, "+
				"so no check would fall inside that window; use a poll interval under %s, or a lifetime over %s",
			cfg.pollInterval,
			cfg.lifetime,
			renewWindow.Round(time.Second),
			renewWindow.Round(time.Second),
			time.Duration(float64(cfg.pollInterval)/renewThreshold).Round(time.Second),
		)
	}
	for _, keyword := range []string{interfacesAll, interfacesDefaultRoute} {
		if len(cfg.interfaces) > 1 && slices.Contains(cfg.interfaces, keyword) {
			return fmt.Errorf(
				"interface selection %q combines %q with other entries; use %q on its own, or name interfaces",
				strings.Join(cfg.interfaces, ","), keyword, keyword,
			)
		}
	}
	// Both retry bounds are conditional because cfg.maxRetries has exactly one
	// consumer, getExternalIPWithRetry, and that is only reached when external
	// IP detection is enabled. With it off nothing retries and nothing waits,
	// so the setting is inert rather than wrong.
	if cfg.externalIP {
		if cfg.maxRetries < minRetries || cfg.maxRetries > maxRetries {
			return fmt.Errorf(
				"maximum retries must be between %d and %d when external IP detection is enabled, got %d",
				minRetries, maxRetries, cfg.maxRetries,
			)
		}
		// Retrying for longer than the poll interval is pointless work: the
		// next poll would have made the same attempt sooner.
		if budget := retryBackoffBudget(cfg.maxRetries); budget > cfg.pollInterval {
			return fmt.Errorf(
				"%d retries wait up to %s between external IP attempts, longer than the %s poll interval; "+
					"use fewer retries, or a longer poll interval",
				cfg.maxRetries, humanDuration(budget), humanDuration(cfg.pollInterval),
			)
		}
	}
	return nil
}

// checkAll runs a poll cycle for every enabled algorithm independently.
func checkAll(
	ctx context.Context,
	cfg *config,
	logger *slog.Logger,
	states map[algorithm]*certState,
	store *statusStore,
) (bool, error) {
	// Gather host info once — shared across all algorithms in this cycle
	hostname, err := os.Hostname()
	if err != nil {
		return false, fmt.Errorf("getting hostname: %w", err)
	}

	discovery := addressDiscovery{internalComplete: true, externalComplete: true}
	if cfg.internalIP {
		internalIPs, err := getInternalIPs(ctx, cfg.interfaces, logger)
		if err != nil {
			logger.Warn("failed to get internal IPs, continuing without them", "err", err)
			discovery.internalComplete = false
		}
		discovery.internalIPs = internalIPs
	}

	if cfg.externalIP {
		// Use the first algorithm's state for the last-known external IP fallback
		lastKnown := states[cfg.algorithms[0]].externalIP
		externalIP, err := getExternalIPWithRetry(ctx, cfg.maxRetries, logger)
		if err != nil {
			logger.Warn("could not determine external IP, using last known value",
				"lastKnown", lastKnown,
				"err", err,
			)
			externalIP = lastKnown
			if externalIP == "" {
				discovery.externalComplete = false
			}
		}
		discovery.externalIP = externalIP
	}

	// Process each algorithm independently — errors are logged but don't stop others.
	allSuccessful := true
	for _, alg := range cfg.algorithms {
		paths := certPathsForAlgorithm(cfg, alg)
		st := states[alg]
		algLogger := logger.With("algorithm", alg)

		if err := checkOne(
			algLogger,
			cfg,
			alg,
			paths,
			st,
			store,
			hostname,
			discovery,
		); err != nil {
			allSuccessful = false
			store.recordError(alg, err)
			algLogger.Error("failed to process certificate, will retry next poll", "err", err)
		}
	}

	return allSuccessful, nil
}

func notifySystemdReady() error {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return nil
	}
	if strings.HasPrefix(socketPath, "@") {
		socketPath = "\x00" + socketPath[1:]
	}

	address := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", nil, address)
	if err != nil {
		return fmt.Errorf("connecting to notification socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("READY=1\nSTATUS=Initial certificate check completed")); err != nil {
		return fmt.Errorf("writing readiness notification: %w", err)
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
	store *statusStore,
	hostname string,
	d addressDiscovery,
) error {
	// Captured before any issuance overwrites it: the internal addresses this
	// process last observed, used to tell a departed address from an
	// unconfirmed one when discovery is incomplete.
	previousInternalIPs := st.internalIPs

	notify := func() error {
		if err := touchNotifyFile(logger, paths.notify); err != nil {
			st.notificationPending = true
			return err
		}
		st.notificationPending = false
		return nil
	}

	// The IP SANs a certificate issued right now would carry. Every branch below
	// resolves this exactly once, and both the comparison and the issuance use
	// that one answer, so the two can never disagree about what belongs in the
	// certificate.
	resolveIPs := func() []net.IP {
		return issuanceIPAddresses(logger, paths.cert, d, previousInternalIPs, cfg.extraIPs)
	}

	issueAndNotify := func(reason string, ipAddresses []net.IP) error {
		logger.Info("issuing certificate", "reason", reason)
		if err := issueCert(logger, cfg, alg, paths, hostname, ipAddresses); err != nil {
			return err
		}
		store.recordRenewal(alg)
		updateState(st, hostname, d)
		// Update status from freshly written cert
		if cert, err := loadCert(paths.cert); err == nil {
			store.setOK(alg, cert)
		}
		st.notificationPending = true
		return notify()
	}

	// Case: cert or key missing
	if !fileExists(paths.cert) || !fileExists(paths.key) {
		return issueAndNotify("missing", resolveIPs())
	}

	// Case: invalid certificate/key pair. Parse the existing certificate and
	// verify that its private key matches the certificate and the algorithm
	// selected for this path.
	cert, err := loadCertificateKeyPair(paths, alg)
	if err != nil {
		logger.Warn("existing certificate/key pair is invalid, re-issuing", "err", err)
		return issueAndNotify("invalid certificate/key pair", resolveIPs())
	}

	// Update store with current cert state
	store.setOK(alg, cert)

	// Case: hostname changed
	if cert.Subject.CommonName != hostname {
		logger.Info("hostname changed", "old", cert.Subject.CommonName, "new", hostname)
		return issueAndNotify("hostname changed", resolveIPs())
	}

	// Case: DNS SANs differ from what this host would be issued now. Comparing
	// the whole set rather than only checking that the hostname appears is what
	// makes a change to the configured names take effect; a containment check
	// would never notice one being added or removed.
	if desiredDNS := certificateDNSNames(hostname, cfg.extraDNS); !stringSetsEqual(cert.DNSNames, desiredDNS) {
		logger.Info("certificate DNS SANs changed", "old", cert.DNSNames, "new", desiredDNS)
		return issueAndNotify("DNS SANs changed", resolveIPs())
	}

	// Case: IP SANs differ from what this host would be issued now. Comparing
	// against the resolved issuance set rather than against raw discovery results
	// means a source that did answer is still acted on when the other did not:
	// interface enumeration is a local syscall that all but always succeeds,
	// while external detection needs the internet and routinely fails, and
	// gating both on one flag left an offline host blind to its own address
	// changes until a renewal happened to fall due. Addresses this cycle could
	// not confirm are carried over by issuanceIPAddresses and so compare equal,
	// which is what keeps an incomplete cycle from reissuing on every poll.
	issueIPs := resolveIPs()
	if !ipAddressSetsEqual(cert.IPAddresses, issueIPs) {
		logger.Info(
			"certificate IP SANs changed",
			"old", ipAddressesToStrings(cert.IPAddresses),
			"new", ipAddressesToStrings(issueIPs),
		)
		return issueAndNotify("IP SANs changed", issueIPs)
	}

	// Case: the configured lifetime no longer matches the certificate. The
	// lifetime is part of the certificate this host should have, exactly like
	// its hostname and its IP SANs, so a change applies at the next poll.
	// Leaving it to the renewal check instead would measure the threshold
	// against the span the old certificate happens to have: shortening the
	// lifetime from a year to a month would then change nothing until the
	// year-long certificate approached its own expiry, eight months later.
	if span := cert.NotAfter.Sub(cert.NotBefore); span != cfg.lifetime {
		logger.Info("configured certificate lifetime changed", "old", span, "new", cfg.lifetime)
		return issueAndNotify("lifetime changed", issueIPs)
	}

	// Case: renewal due
	if needsRenewal(cert, renewThreshold) {
		logger.Info("certificate approaching expiry",
			"notAfter", cert.NotAfter,
			"remaining", time.Until(cert.NotAfter).Round(time.Hour),
		)
		return issueAndNotify("renewal due", issueIPs)
	}

	staleNotification := false
	if !st.notificationPending {
		staleNotification, err = notificationOlderThanCertificate(paths)
		if err != nil {
			return fmt.Errorf("checking notification state: %w", err)
		}
	}
	if st.notificationPending || staleNotification {
		logger.Info("retrying certificate update notification", "path", paths.notify)
		return notify()
	}

	// No action needed — update state on first successful poll
	updateState(st, hostname, d)
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
	ipAddresses []net.IP,
) error {
	logger.Info("issuing certificate",
		"hostname", hostname,
		"ipSANs", ipAddressesToStrings(ipAddresses),
		"lifetime", cfg.lifetime,
	)

	certDER, keyPEM, err := generateCert(alg, cfg, hostname, ipAddresses)
	if err != nil {
		return fmt.Errorf("generating certificate: %w", err)
	}

	if err := os.MkdirAll(cfg.certDir, 0750); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := replaceCertificateFiles(paths, certPEM, keyPEM); err != nil {
		return err
	}
	if _, err := loadCertificateKeyPair(paths, alg); err != nil {
		return fmt.Errorf("validating written certificate/key pair: %w", err)
	}

	logger.Info("certificate issued successfully", "cert", paths.cert, "key", paths.key)
	return nil
}

// generateCert builds the x509 template and dispatches to the right key generator.
func generateCert(alg algorithm, cfg *config, hostname string, ipAddresses []net.IP) (certDER []byte, keyPEM []byte, err error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	notBefore := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     certificateDNSNames(hostname, cfg.extraDNS),
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

// numericSAN matches an entry made only of the characters an IP address uses.
// One that fails to parse is a mistyped address rather than a host name, and is
// rejected instead of being quietly certified as a DNS name.
var numericSAN = regexp.MustCompile(`^[0-9.:]+$`)

// classifyExtraSANs splits configured subject alternative names into addresses
// and host names. An entry that parses as an IP becomes an IP SAN; anything
// else must be a syntactically valid DNS name.
func classifyExtraSANs(entries []string) ([]net.IP, []string, error) {
	var ips []net.IP
	var names []string
	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if numericSAN.MatchString(entry) {
			return nil, nil, fmt.Errorf("%q is not a valid IP address", entry)
		}
		if !validDNSName(entry) {
			return nil, nil, fmt.Errorf("%q is not a valid IP address or DNS name", entry)
		}
		names = append(names, entry)
	}
	return ips, names, nil
}

// validDNSName reports whether a name can be used as a DNS subject alternative
// name. A leading "*." is accepted, since a wildcard covers the leftmost label.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	if rest, found := strings.CutPrefix(name, "*."); found {
		name = rest
	}
	if name == "" {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

// addressIP extracts the IP from an interface address, or nil if it carries none.
func addressIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// usableInternalIP reports whether an address belongs in a certificate.
// Link-local addresses do not: 169.254/16 is what a host assigns itself when
// DHCP has failed, so it appears when the lease is lost and disappears when it
// returns, re-issuing the certificate each way to name an address that nothing
// can reach the host on.
func usableInternalIP(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// defaultRouteInterface returns the interface carrying the host's default
// route, the one it would use to reach anything not on a local network.
//
// A connected UDP socket transmits nothing: the kernel resolves the route and
// picks the source address it would use, and that address identifies the
// interface. An error means the host has no default route — an isolated
// network, or a lapsed DHCP lease.
func defaultRouteInterface(ctx context.Context) (string, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", defaultRouteProbe)
	if err != nil {
		return "", fmt.Errorf("resolving default route: %w", err)
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if closeErr := conn.Close(); closeErr != nil {
		return "", fmt.Errorf("closing default route probe: %w", closeErr)
	}
	if !ok || local.IP == nil {
		return "", errors.New("default route probe reported no source address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("listing addresses of %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			if ip := addressIP(addr); ip != nil && ip.Equal(local.IP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface holds the default route source address %s", local.IP)
}

// selectedInterfaces resolves the configured selection to the interface names
// whose addresses belong in the certificate, or nil when every non-loopback
// interface qualifies.
func selectedInterfaces(ctx context.Context, selection []string, logger *slog.Logger) map[string]struct{} {
	if len(selection) == 1 && selection[0] == interfacesAll {
		return nil
	}
	if !followsDefaultRoute(selection) {
		set := make(map[string]struct{}, len(selection))
		for _, name := range selection {
			set[name] = struct{}{}
		}
		return set
	}

	name, err := defaultRouteInterface(ctx)
	if err != nil {
		// Without a default route there is nothing to follow, so fall back to
		// what certd did before: every non-loopback interface. Issuing a
		// certificate with no addresses at all would be worse.
		logger.Warn("no default route, falling back to every non-loopback interface", "err", err)
		return nil
	}
	return map[string]struct{}{name: {}}
}

// getInternalIPs returns the IPv4 addresses of the selected interfaces.
func getInternalIPs(ctx context.Context, selection []string, logger *slog.Logger) ([]string, error) {
	wanted := selectedInterfaces(ctx, selection, logger)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var ips []string
	found := make(map[string]struct{}, len(wanted))
	for _, iface := range ifaces {
		if wanted != nil {
			if _, ok := wanted[iface.Name]; !ok {
				continue
			}
			found[iface.Name] = struct{}{}
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			// Skipping would return a list the caller cannot tell from a
			// complete one, and the addresses left out of it look to the caller
			// like addresses that have gone away, so they get pruned from the
			// certificate. Report the failure instead of hiding it.
			return nil, fmt.Errorf("listing addresses of %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			if ip := addressIP(addr); usableInternalIP(ip) {
				ips = append(ips, ip.String())
			}
		}
	}

	for name := range wanted {
		if _, ok := found[name]; !ok {
			logger.Warn("configured interface does not exist", "interface", name)
		}
	}
	return ips, nil
}

// followsDefaultRoute reports whether a selection asks for the interface that
// carries the default route, either by naming it or by saying nothing at all.
func followsDefaultRoute(selection []string) bool {
	return len(selection) == 0 || (len(selection) == 1 && selection[0] == interfacesDefaultRoute)
}

// interfaceSelectionText describes an interface selection for logging, naming
// the default behaviour rather than reporting it as an empty setting.
func interfaceSelectionText(selection []string) string {
	if followsDefaultRoute(selection) {
		return interfacesDefaultRoute
	}
	return strings.Join(selection, ",")
}

// retryBackoffBudget returns the delay getExternalIPWithRetry spends waiting
// across the given number of attempts, which wait one fewer time than they
// attempt since nothing is waited after the last one.
//
// It counts only the waiting, not the attempts themselves: a provider that
// refuses a connection fails at once, while one that black-holes it costs a
// further timeout per provider. That cost is contingent on how the network
// fails, whereas the backoff is paid every time.
func retryBackoffBudget(attempts int) time.Duration {
	var total time.Duration
	backoff := time.Second
	for range attempts - 1 {
		total += backoff
		backoff = nextBackoff(backoff)
	}
	return total
}

// nextBackoff returns the delay to wait after a failed attempt, doubling up to
// maxBackoff and holding there.
func nextBackoff(current time.Duration) time.Duration {
	if next := current * 2; next < maxBackoff {
		return next
	}
	return maxBackoff
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
		// The delay belongs between attempts, so there is none after the last
		// one: waiting there only postpones the error already being returned,
		// and does so for the longest interval of the whole schedule.
		if attempt == maxRetries {
			break
		}
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
			backoff = nextBackoff(backoff)
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
		// The body of an unsuccessful response is not an answer, however much
		// it may look like one: a proxy or captive portal replying 429 or 503
		// with something address-shaped is describing itself, not this host.
		// Without this the first such reply is taken as the external address
		// and the providers that would have answered are never asked.
		if resp.StatusCode != http.StatusOK {
			logger.Warn("external IP provider returned an unexpected status",
				"provider", provider, "status", resp.Status)
			if closeErr := resp.Body.Close(); closeErr != nil {
				logger.Warn("external IP provider response body close failed",
					"provider", provider, "err", closeErr)
			}
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

// needsRenewal returns true when less than threshold fraction of lifetime
// remains. The certificate's own span is the right measure here only because
// the lifetime check above guarantees it equals the configured lifetime by the
// time this runs.
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

func loadCertificateKeyPair(paths certPaths, alg algorithm) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(paths.cert)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(paths.key)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading certificate/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate/key pair contains no certificates")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	if !certificateUsesAlgorithm(cert, alg) {
		return nil, fmt.Errorf(
			"certificate uses %s public key, expected %s",
			cert.PublicKeyAlgorithm,
			alg,
		)
	}
	return cert, nil
}

func certificateUsesAlgorithm(cert *x509.Certificate, alg algorithm) bool {
	switch alg {
	case algorithmRSA:
		return cert.PublicKeyAlgorithm == x509.RSA
	case algorithmECDSA:
		return cert.PublicKeyAlgorithm == x509.ECDSA
	case algorithmEd25519:
		return cert.PublicKeyAlgorithm == x509.Ed25519
	default:
		return false
	}
}

func replaceCertificateFiles(paths certPaths, certPEM, keyPEM []byte) error {
	certDir := filepath.Dir(paths.cert)
	if keyDir := filepath.Dir(paths.key); keyDir != certDir {
		return fmt.Errorf("certificate and key must use the same directory: %s != %s", certDir, keyDir)
	}

	keyTemp, err := stageFileForReplacement(paths.key, keyPEM, 0640)
	if err != nil {
		return fmt.Errorf("staging private key: %w", err)
	}
	defer func() { _ = os.Remove(keyTemp) }()

	certTemp, err := stageFileForReplacement(paths.cert, certPEM, 0640)
	if err != nil {
		return fmt.Errorf("staging certificate: %w", err)
	}
	defer func() { _ = os.Remove(certTemp) }()

	// Publish the certificate last. Consumers that react to certificate changes
	// will therefore only observe the new certificate after its key is in place.
	if err := os.Rename(keyTemp, paths.key); err != nil {
		return fmt.Errorf("replacing private key: %w", err)
	}
	if err := os.Rename(certTemp, paths.cert); err != nil {
		return fmt.Errorf("replacing certificate: %w", err)
	}

	dir, err := os.Open(certDir)
	if err != nil {
		return fmt.Errorf("opening certificate directory for sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("syncing certificate directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("closing certificate directory: %w", err)
	}
	return nil
}

func stageFileForReplacement(target string, data []byte, mode fs.FileMode) (string, error) {
	temp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return "", err
	}
	tempPath := temp.Name()
	fail := func(err error) (string, error) {
		_ = temp.Close()
		_ = os.Remove(tempPath)
		return "", err
	}

	if err := temp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := temp.Write(data); err != nil {
		return fail(err)
	}
	if err := temp.Sync(); err != nil {
		return fail(err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	return tempPath, nil
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

func notificationOlderThanCertificate(paths certPaths) (bool, error) {
	certInfo, err := os.Stat(paths.cert)
	if err != nil {
		return false, fmt.Errorf("stating certificate: %w", err)
	}
	keyInfo, err := os.Stat(paths.key)
	if err != nil {
		return false, fmt.Errorf("stating private key: %w", err)
	}
	notifyInfo, err := os.Stat(paths.notify)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("stating notification file: %w", err)
	}
	if !notifyInfo.Mode().IsRegular() {
		return true, nil
	}

	latestCertificateUpdate := certInfo.ModTime()
	if keyInfo.ModTime().After(latestCertificateUpdate) {
		latestCertificateUpdate = keyInfo.ModTime()
	}
	return notifyInfo.ModTime().Before(latestCertificateUpdate), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// updateState records this cycle's observations. Only authoritative results are
// stored: a failed discovery must not erase what an earlier cycle established,
// because that record is what lets a later issuance tell an address that has
// gone away from one this cycle simply could not confirm.
func updateState(st *certState, hostname string, d addressDiscovery) {
	st.hostname = hostname
	if d.internalComplete {
		st.internalIPs = d.internalIPs
	}
	if d.externalComplete {
		st.externalIP = d.externalIP
	}
}

// certificateIPAddresses returns the IP SANs for a certificate: the loopback
// address, whatever discovery found, and the addresses configured explicitly.
// The result is deduplicated and ordered, so two certificates built from the
// same inputs are byte-identical in this respect and can be compared by eye.
//
// Configured addresses are included whether or not this host holds them. That
// is the point of them: a floating address belongs in the certificates of every
// node that might take it over, not only the one holding it at issuance.
func certificateIPAddresses(internalIPs []string, externalIP string, extra []net.IP) []net.IP {
	candidates := make([]string, 0, 1+len(internalIPs)+1)
	candidates = append(candidates, "127.0.0.1")
	candidates = append(candidates, internalIPs...)
	if externalIP != "" {
		candidates = append(candidates, externalIP)
	}

	seen := make(map[string]struct{}, len(candidates)+len(extra))
	ips := make([]net.IP, 0, len(candidates)+len(extra))
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		canonical := ip.String()
		if _, exists := seen[canonical]; exists {
			return
		}
		seen[canonical] = struct{}{}
		ips = append(ips, ip)
	}
	for _, candidate := range candidates {
		add(net.ParseIP(candidate))
	}
	for _, ip := range extra {
		add(ip)
	}

	slices.SortFunc(ips, func(a, b net.IP) int { return bytes.Compare(a.To16(), b.To16()) })
	return ips
}

// certificateDNSNames returns the DNS SANs for a certificate, deduplicated and
// ordered for the same reason as the addresses.
func certificateDNSNames(hostname string, extra []string) []string {
	names := make([]string, 0, 2+len(extra))
	seen := make(map[string]struct{}, 2+len(extra))
	for _, name := range append([]string{hostname, "localhost"}, extra...) {
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// stringSetsEqual reports whether two lists hold the same entries, ignoring
// order and repetition.
func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		aSet := make(map[string]struct{}, len(a))
		for _, v := range a {
			aSet[v] = struct{}{}
		}
		bSet := make(map[string]struct{}, len(b))
		for _, v := range b {
			bSet[v] = struct{}{}
		}
		if len(aSet) != len(bSet) {
			return false
		}
		for v := range aSet {
			if _, ok := bSet[v]; !ok {
				return false
			}
		}
		return true
	}
	sortedA := slices.Clone(a)
	sortedB := slices.Clone(b)
	slices.Sort(sortedA)
	slices.Sort(sortedB)
	return slices.Equal(sortedA, sortedB)
}

// issuanceIPAddresses returns the IP SANs to embed in a certificate that is
// about to be issued. When address discovery succeeded, that is exactly what
// was discovered. When it did not, issuing with only the addresses that were
// found would silently drop the rest — including from certificates reissued
// for an unrelated reason such as a hostname change or a due renewal — so the
// SANs of the existing certificate that this cycle could not confirm are
// retained alongside them. The next poll with complete discovery reconciles
// the set.
func issuanceIPAddresses(
	logger *slog.Logger,
	certPath string,
	d addressDiscovery,
	previousInternalIPs []string,
	extra []net.IP,
) []net.IP {
	discovered := certificateIPAddresses(d.internalIPs, d.externalIP, extra)
	if d.complete() {
		return discovered
	}

	existing, err := loadCert(certPath)
	if err != nil {
		logger.Warn("address discovery incomplete and no usable certificate to retain IP SANs from, "+
			"the new certificate may be missing addresses",
			"ipSANs", ipAddressesToStrings(discovered),
			"err", err,
		)
		return discovered
	}

	merged := mergeIPAddresses(discovered, retainableIPAddresses(existing.IPAddresses, d, previousInternalIPs))
	if !ipAddressSetsEqual(merged, discovered) {
		logger.Warn("address discovery incomplete, retaining unconfirmed IP SANs from the existing certificate",
			"discovered", ipAddressesToStrings(discovered),
			"ipSANs", ipAddressesToStrings(merged),
		)
	}
	return merged
}

// retainableIPAddresses returns the addresses of an existing certificate that
// this cycle could not confirm, and which must therefore be carried over into a
// reissued certificate. An address that a working source positively contradicts
// is not retained: one that an earlier cycle recorded on a local interface, and
// that successful enumeration no longer reports, has gone away rather than
// merely being unconfirmed. Without that distinction a host whose external IP
// detection is permanently failing would accumulate every internal address it
// ever held, since no later poll could ever prune them.
func retainableIPAddresses(existing []net.IP, d addressDiscovery, previousInternalIPs []string) []net.IP {
	var departed map[string]struct{}
	if d.internalComplete {
		departed = make(map[string]struct{}, len(previousInternalIPs))
		for _, raw := range previousInternalIPs {
			if ip := net.ParseIP(raw); ip != nil {
				departed[ip.String()] = struct{}{}
			}
		}
		for _, raw := range d.internalIPs {
			if ip := net.ParseIP(raw); ip != nil {
				delete(departed, ip.String())
			}
		}
	}

	retained := make([]net.IP, 0, len(existing))
	for _, ip := range existing {
		if _, gone := departed[ip.String()]; gone {
			continue
		}
		retained = append(retained, ip)
	}
	return retained
}

// mergeIPAddresses returns the union of two address lists, preserving the order
// of primary and appending the addresses of extra that it does not contain.
func mergeIPAddresses(primary, extra []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(primary)+len(extra))
	merged := make([]net.IP, 0, len(primary)+len(extra))
	for _, list := range [][]net.IP{primary, extra} {
		for _, ip := range list {
			canonical := ip.String()
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			merged = append(merged, ip)
		}
	}
	return merged
}

func ipAddressSetsEqual(a, b []net.IP) bool {
	aSet := make(map[string]struct{}, len(a))
	for _, ip := range a {
		aSet[ip.String()] = struct{}{}
	}
	bSet := make(map[string]struct{}, len(b))
	for _, ip := range b {
		bSet[ip.String()] = struct{}{}
	}
	if len(aSet) != len(bSet) {
		return false
	}
	for ip := range aSet {
		if _, exists := bSet[ip]; !exists {
			return false
		}
	}
	return true
}

func ipAddressesToStrings(ips []net.IP) []string {
	values := make([]string, len(ips))
	for i, ip := range ips {
		values[i] = ip.String()
	}
	return values
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

// newHTTPServer creates the HTTP server with /health and /metrics endpoints.
func newHTTPServer(cfg *config, store *statusStore, startTime time.Time, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth(cfg, store, logger))
	mux.HandleFunc("/metrics", handleMetrics(cfg, store, startTime))
	return &http.Server{
		Addr:         cfg.httpAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

// handleHealth returns a handler for the /health endpoint.
// Returns 200 if all certs are healthy, 503 if any have errors.
func handleHealth(cfg *config, store *statusStore, logger *slog.Logger) http.HandlerFunc {
	type certHealth struct {
		Status    string   `json:"status"`
		Error     string   `json:"error,omitempty"`
		Subject   string   `json:"subject,omitempty"`
		NotBefore string   `json:"not_before,omitempty"`
		NotAfter  string   `json:"not_after,omitempty"`
		Remaining string   `json:"remaining,omitempty"`
		SANDNS    []string `json:"san_dns,omitempty"`
		SANIP     []string `json:"san_ip,omitempty"`
	}
	type response struct {
		Status string                `json:"status"`
		Certs  map[string]certHealth `json:"certs"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := store.snapshot()
		certs := make(map[string]certHealth, len(cfg.algorithms))
		allOK := true

		for _, alg := range cfg.algorithms {
			st := snapshot[alg]
			if st.err != nil || st.notAfter.IsZero() {
				allOK = false
				errMsg := "certificate not yet issued"
				if st.err != nil {
					errMsg = st.err.Error()
				}
				certs[string(alg)] = certHealth{Status: "error", Error: errMsg}
				continue
			}
			remaining := time.Until(st.notAfter)
			ch := certHealth{
				Status:    "ok",
				Subject:   st.subject,
				NotBefore: st.notBefore.UTC().Format(time.RFC3339),
				NotAfter:  st.notAfter.UTC().Format(time.RFC3339),
				Remaining: remaining.Round(time.Hour).String(),
				SANDNS:    st.dnsNames,
				SANIP:     st.ipAddrs,
			}
			if remaining <= 0 {
				allOK = false
				ch.Status = "expired"
			}
			certs[string(alg)] = ch
		}

		resp := response{
			Status: "ok",
			Certs:  certs,
		}
		if !allOK {
			resp.Status = "error"
		}

		w.Header().Set("Content-Type", "application/json")
		if !allOK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Warn("failed to write health response", "err", err)
		}
	}
}

// handleMetrics returns a handler for the /metrics endpoint (Prometheus text format).
func handleMetrics(cfg *config, store *statusStore, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := store.snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		ew := &errWriter{w: w}

		ew.printf("# HELP certd_up Whether certd is running (always 1)\n")
		ew.printf("# TYPE certd_up gauge\n")
		ew.printf("certd_up 1\n\n")

		ew.printf("# HELP certd_start_time_seconds Unix timestamp when certd started\n")
		ew.printf("# TYPE certd_start_time_seconds gauge\n")
		ew.printf("certd_start_time_seconds %d\n\n", startTime.Unix())

		ew.printf("# HELP certd_cert_not_before_seconds Certificate validity start as Unix timestamp\n")
		ew.printf("# TYPE certd_cert_not_before_seconds gauge\n")
		for _, alg := range cfg.algorithms {
			st := snapshot[alg]
			if !st.notBefore.IsZero() {
				ew.printf("certd_cert_not_before_seconds{algorithm=%q} %d\n", alg, st.notBefore.Unix())
			}
		}
		ew.printf("\n")

		ew.printf("# HELP certd_cert_not_after_seconds Certificate expiry as Unix timestamp\n")
		ew.printf("# TYPE certd_cert_not_after_seconds gauge\n")
		for _, alg := range cfg.algorithms {
			st := snapshot[alg]
			if !st.notAfter.IsZero() {
				ew.printf("certd_cert_not_after_seconds{algorithm=%q} %d\n", alg, st.notAfter.Unix())
			}
		}
		ew.printf("\n")

		ew.printf("# HELP certd_cert_renewals_total Total number of times a certificate was issued or renewed\n")
		ew.printf("# TYPE certd_cert_renewals_total counter\n")
		for _, alg := range cfg.algorithms {
			ew.printf("certd_cert_renewals_total{algorithm=%q} %d\n", alg, snapshot[alg].renewals)
		}
		ew.printf("\n")

		ew.printf("# HELP certd_cert_errors_total Total number of failed certificate issue attempts\n")
		ew.printf("# TYPE certd_cert_errors_total counter\n")
		for _, alg := range cfg.algorithms {
			ew.printf("certd_cert_errors_total{algorithm=%q} %d\n", alg, snapshot[alg].errors)
		}

		// Writes to http.ResponseWriter rarely fail (client disconnect), nothing to do
		// beyond letting the connection close naturally — but errcheck requires we
		// acknowledge the error.
		_ = ew.err
	}
}

// errWriter wraps an io.Writer and tracks the first write error,
// allowing subsequent writes to be skipped silently.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

// parseConfig reads CLI flags and env vars; CLI flags take precedence over env vars.
func parseConfig() *config {
	// Need a bootstrap logger for duration parse warnings before the main logger is set up
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	var useRSA, useECDSA, useEd25519 bool

	flag.BoolVar(&useRSA, "rsa", envBoolOrDefault("CERTD_RSA", defaultRSA),
		"Generate and manage RSA 4096 certificate (env: CERTD_RSA)")
	flag.BoolVar(&useECDSA, "ecdsa", envBoolOrDefault("CERTD_ECDSA", defaultECDSA),
		"Generate and manage ECDSA P-256 certificate (env: CERTD_ECDSA)")
	flag.BoolVar(&useEd25519, "ed25519", envBoolOrDefault("CERTD_ED25519", defaultEd25519),
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
	flag.BoolVar(&cfg.internalIP, "internal-ip", envBoolOrDefault("CERTD_INTERNAL_IP", defaultInternalIP),
		"Include internal IPs in certificate SANs (env: CERTD_INTERNAL_IP)")
	var extraSANsStr string
	flag.StringVar(&extraSANsStr, "extra-sans", envOrDefault("CERTD_EXTRA_SANS", ""),
		"Additional subject alternative names, comma separated: IP addresses or DNS names, "+
			"always certified whether or not this host holds them (env: CERTD_EXTRA_SANS)")
	var interfacesStr string
	flag.StringVar(&interfacesStr, "interfaces", envOrDefault("CERTD_INTERFACES", ""),
		`Interfaces to take internal IPs from: "`+interfacesDefaultRoute+`" (the default), "`+interfacesAll+
			`" for every non-loopback interface, or a comma-separated list of names (env: CERTD_INTERFACES)`)
	flag.BoolVar(&cfg.externalIP, "external-ip", envBoolOrDefault("CERTD_EXTERNAL_IP", defaultExternalIP),
		"Include external IP in certificate SANs (env: CERTD_EXTERNAL_IP)")
	flag.IntVar(&cfg.maxRetries, "max-retries", envIntOrDefault("CERTD_MAX_RETRIES", defaultMaxRetries),
		"Max retries for external IP detection (env: CERTD_MAX_RETRIES)")
	flag.StringVar(&cfg.httpAddr, "http-addr", envOrDefault("CERTD_HTTP_ADDR", defaultHTTPAddr),
		"Address for HTTP health/metrics server, empty string to disable (env: CERTD_HTTP_ADDR)")
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

	cfg.interfaces = splitList(interfacesStr)

	extraIPs, extraDNS, err := classifyExtraSANs(splitList(extraSANsStr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -extra-sans value %q: %v\n", extraSANsStr, err)
		os.Exit(1)
	}
	cfg.extraIPs, cfg.extraDNS = extraIPs, extraDNS

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

// humanDuration renders a duration using the extended units parseDuration
// accepts, so a configuration bound reads as "25y" rather than "219000h0m0s".
// Whatever it returns parses back to the same value, because operators are
// expected to copy it into their configuration.
func humanDuration(d time.Duration) string {
	switch {
	case d >= 8760*time.Hour && d%(8760*time.Hour) == 0:
		return fmt.Sprintf("%dy", d/(8760*time.Hour))
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// maxDuration is the largest value a time.Duration can represent, a little over
// 292 years. Any input implying more than this is rejected rather than wrapped.
const maxDuration = time.Duration(1<<63 - 1)

// parseDuration extends Go's time.ParseDuration with support for:
//
//	y = 365 * 24h
//	w = 7 * 24h
//	d = 24h
//
// Units can be combined: "1y30d", "2w3d12h", "90d". Counts are checked against
// what a time.Duration can hold, so an input larger than roughly 292 years is
// an error rather than a wrapped, and possibly negative, value.
func parseDuration(s string) (time.Duration, error) {
	tooLong := func() error {
		return fmt.Errorf("invalid duration %q: longer than the maximum of about 292 years", s)
	}

	var total time.Duration
	var remainder strings.Builder
	consumed := 0

	for _, match := range extendedDurationRe.FindAllStringSubmatchIndex(s, -1) {
		remainder.WriteString(s[consumed:match[0]])
		consumed = match[1]

		digits := s[match[2]:match[3]]
		count, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %s is out of range", s, digits)
		}

		var unit time.Duration
		switch s[match[4]:match[5]] {
		case "y":
			unit = 8760 * time.Hour
		case "w":
			unit = 168 * time.Hour
		case "d":
			unit = 24 * time.Hour
		}

		if count > int64(maxDuration/unit) {
			return 0, tooLong()
		}
		scaled := time.Duration(count) * unit
		if total > maxDuration-scaled {
			return 0, tooLong()
		}
		total += scaled
	}
	remainder.WriteString(s[consumed:])

	if rest := remainder.String(); rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		// Only a positive remainder can overflow: total is never negative, so
		// adding a negative one cannot fall below the minimum.
		if d > 0 && total > maxDuration-d {
			return 0, tooLong()
		}
		total += d
	}

	if total == 0 && s != "0" {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total, nil
}

// splitList parses a comma-separated setting, discarding surrounding spaces and
// empty entries so that "eth0, eth1" and a trailing comma both behave.
func splitList(value string) []string {
	var items []string
	for item := range strings.SplitSeq(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
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
