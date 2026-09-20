// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Krzysztof Ciepłucha

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunRejectsInvalidConfigBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*config)
		wantError string
	}{
		{
			name: "zero poll interval",
			configure: func(cfg *config) {
				cfg.pollInterval = 0
			},
			wantError: "poll interval must be between",
		},
		{
			name: "negative poll interval",
			configure: func(cfg *config) {
				cfg.pollInterval = -time.Second
			},
			wantError: "poll interval must be between",
		},
		{
			name: "poll interval below minimum",
			configure: func(cfg *config) {
				cfg.pollInterval = time.Second
			},
			wantError: "poll interval must be between",
		},
		{
			name: "zero certificate lifetime",
			configure: func(cfg *config) {
				cfg.lifetime = 0
			},
			wantError: "certificate lifetime must be between",
		},
		{
			name: "certificate lifetime below minimum",
			configure: func(cfg *config) {
				cfg.lifetime = 30 * time.Minute
			},
			wantError: "certificate lifetime must be between",
		},
		{
			name: "poll interval too long to renew in time",
			configure: func(cfg *config) {
				cfg.lifetime = 3 * time.Hour
				cfg.pollInterval = time.Hour
			},
			wantError: "no check would fall inside that window",
		},
		{
			name: "zero external IP retries",
			configure: func(cfg *config) {
				cfg.externalIP = true
				cfg.maxRetries = 0
			},
			wantError: "maximum retries must be between",
		},
		{
			name: "certificate lifetime above maximum",
			configure: func(cfg *config) {
				cfg.lifetime = maxLifetime + time.Hour
			},
			wantError: "certificate lifetime must be between",
		},
		{
			name: "poll interval above maximum",
			configure: func(cfg *config) {
				cfg.lifetime = maxLifetime
				cfg.pollInterval = maxPollInterval + time.Minute
			},
			wantError: "poll interval must be between",
		},
		{
			name: "interface selection mixes all with names",
			configure: func(cfg *config) {
				cfg.interfaces = []string{interfacesAll, "eth0"}
			},
			wantError: "combines",
		},
		{
			name: "interface selection mixes default-route with names",
			configure: func(cfg *config) {
				cfg.interfaces = []string{interfacesDefaultRoute, "eth0"}
			},
			wantError: "combines",
		},
		{
			name: "interface selection combines both keywords",
			configure: func(cfg *config) {
				cfg.interfaces = []string{interfacesAll, interfacesDefaultRoute}
			},
			wantError: "combines",
		},
		{
			name: "more retries than permitted",
			configure: func(cfg *config) {
				cfg.externalIP = true
				cfg.maxRetries = maxRetries + 1
			},
			wantError: "maximum retries must be between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, paths, logger := newTestCertificateConfig(t, false, false)
			cfg.algorithms = []algorithm{algorithmECDSA}
			cfg.pollInterval = time.Hour
			cfg.maxRetries = 1
			cfg.httpAddr = ""
			tt.configure(cfg)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := run(ctx, cfg, logger)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("run error = %v, want error containing %q", err, tt.wantError)
			}
			if fileExists(paths.cert) || fileExists(paths.key) {
				t.Fatal("invalid configuration produced certificate files")
			}
		})
	}
}

func TestValidateConfigBoundsRetriesByPollInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		externalIP bool
		retries    int
		poll       time.Duration
		wantError  string
	}{
		{name: "default retries at the shortest poll", externalIP: true, retries: defaultMaxRetries, poll: time.Minute},
		{name: "most retries a one minute poll affords", externalIP: true, retries: 7, poll: time.Minute},
		{name: "most retries at all, with room for them", externalIP: true, retries: maxRetries, poll: 5 * time.Minute},
		{
			name: "retries outlast the poll interval", externalIP: true, retries: maxRetries, poll: time.Minute,
			wantError: "longer than the",
		},
		{
			name: "more retries than permitted", externalIP: true, retries: maxRetries + 1, poll: time.Hour,
			wantError: "maximum retries must be between",
		},
		// With external IP detection off nothing retries and nothing waits, so
		// the setting is inert and is not held against the poll interval.
		{name: "unused retries are not checked", externalIP: false, retries: maxRetries, poll: time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config{
				algorithms:   []algorithm{algorithmECDSA},
				lifetime:     defaultLifetime,
				pollInterval: tt.poll,
				externalIP:   tt.externalIP,
				maxRetries:   tt.retries,
			}
			err := validateConfig(cfg)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateConfig(%d retries, %s poll) = %v, want nil", tt.retries, tt.poll, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateConfig(%d retries, %s poll) = %v, want error containing %q",
					tt.retries, tt.poll, err, tt.wantError)
			}
		})
	}
}

func TestValidateConfigAcceptsConfigurationsThatCanRenewInTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		lifetime     time.Duration
		pollInterval time.Duration
	}{
		{name: "built-in defaults", lifetime: defaultLifetime, pollInterval: defaultPollInterval},
		{name: "packaged unit", lifetime: defaultLifetime, pollInterval: 5 * time.Minute},
		{name: "shortest permitted lifetime", lifetime: minLifetime, pollInterval: minPollInterval},
		{name: "poll just inside the renewal window", lifetime: 3 * time.Hour, pollInterval: time.Hour - time.Second},
		{name: "documented override example", lifetime: 10 * 8760 * time.Hour, pollInterval: 5 * time.Minute},
		{name: "widest permitted pairing", lifetime: maxLifetime, pollInterval: maxPollInterval},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config{
				algorithms:   []algorithm{algorithmECDSA},
				lifetime:     tt.lifetime,
				pollInterval: tt.pollInterval,
				maxRetries:   defaultMaxRetries,
			}
			if err := validateConfig(cfg); err != nil {
				t.Fatalf("validateConfig(%s lifetime, %s poll) = %v, want nil",
					tt.lifetime, tt.pollInterval, err)
			}
		})
	}
}

func TestRunReturnsHTTPBindErrorBeforeCertificateIssuance(t *testing.T) {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve HTTP address: %v", err)
	}
	defer func() { _ = listener.Close() }()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	cfg.algorithms = []algorithm{algorithmECDSA}
	cfg.pollInterval = time.Hour
	cfg.httpAddr = listener.Addr().String()

	err = run(context.Background(), cfg, logger)
	if err == nil || !strings.Contains(err.Error(), "binding HTTP server") {
		t.Fatalf("run error = %v, want HTTP bind error", err)
	}
	if fileExists(paths.cert) || fileExists(paths.key) {
		t.Fatal("HTTP bind failure produced certificate files")
	}
}

func TestRunNotifiesSystemdAfterInitialCertificateCycle(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "certd-notify-")
	if err != nil {
		t.Fatalf("create notification socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen on notification socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("NOTIFY_SOCKET", socketPath)

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	cfg.algorithms = []algorithm{algorithmECDSA}
	cfg.pollInterval = time.Hour
	cfg.httpAddr = ""

	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(ctx, cfg, logger)
	}()

	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set notification read deadline: %v", err)
	}
	message := make([]byte, 256)
	n, _, err := listener.ReadFromUnix(message)
	if err != nil {
		cancel()
		t.Fatalf("read readiness notification: %v", err)
	}
	if got, want := string(message[:n]), "READY=1\nSTATUS=Initial certificate check completed"; got != want {
		cancel()
		t.Fatalf("readiness notification = %q, want %q", got, want)
	}
	if _, err := loadCertificateKeyPair(paths, algorithmECDSA); err != nil {
		cancel()
		t.Fatalf("certificate was not ready before notification: %v", err)
	}

	cancel()
	select {
	case err := <-runResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run returned %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop after context cancellation")
	}
}

func TestCheckOneReissuesMismatchedCertificateKeyPair(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, certificateIPAddresses(nil, "", nil)); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	initial := loadTestCertificate(t, paths.cert)

	_, replacementKey, err := generateCert(algorithmECDSA, cfg, hostname, certificateIPAddresses(nil, "", nil))
	if err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	if err := os.WriteFile(paths.key, replacementKey, 0600); err != nil {
		t.Fatalf("replace private key: %v", err)
	}

	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		hostname,
		completeDiscovery(nil, ""),
	); err != nil {
		t.Fatalf("repair certificate/key pair: %v", err)
	}

	repaired, err := loadCertificateKeyPair(paths, algorithmECDSA)
	if err != nil {
		t.Fatalf("load repaired certificate/key pair: %v", err)
	}
	if initial.SerialNumber.Cmp(repaired.SerialNumber) == 0 {
		t.Fatal("certificate was not reissued for a mismatched private key")
	}
}

func TestCheckOneReissuesCertificateWithWrongAlgorithm(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	if err := issueCert(logger, cfg, algorithmEd25519, paths, hostname, certificateIPAddresses(nil, "", nil)); err != nil {
		t.Fatalf("issue certificate with wrong algorithm: %v", err)
	}

	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		hostname,
		completeDiscovery(nil, ""),
	); err != nil {
		t.Fatalf("repair certificate algorithm: %v", err)
	}
	cert, err := loadCertificateKeyPair(paths, algorithmECDSA)
	if err != nil {
		t.Fatalf("load repaired certificate/key pair: %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("public key algorithm = %s, want ECDSA", cert.PublicKeyAlgorithm)
	}
}

func TestIssueCertAtomicallyReplacesFilesAndModes(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	for _, path := range []string{paths.cert, paths.key} {
		if err := os.WriteFile(path, []byte("old data"), 0600); err != nil {
			t.Fatalf("create existing file: %v", err)
		}
		//nolint:gosec // Test verifies that overly broad existing modes are corrected.
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatalf("set existing file mode: %v", err)
		}
	}

	if err := issueCert(logger, cfg, algorithmECDSA, paths, "host.example.test", certificateIPAddresses(nil, "", nil)); err != nil {
		t.Fatalf("replace certificate/key pair: %v", err)
	}
	if _, err := loadCertificateKeyPair(paths, algorithmECDSA); err != nil {
		t.Fatalf("load replacement certificate/key pair: %v", err)
	}
	for _, path := range []string{paths.cert, paths.key} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat replacement file: %v", err)
		}
		if got, want := info.Mode().Perm(), os.FileMode(0640); got != want {
			t.Errorf("mode for %s = %o, want %o", path, got, want)
		}
	}
	tempFiles, err := filepath.Glob(filepath.Join(cfg.certDir, ".*.tmp-*"))
	if err != nil {
		t.Fatalf("find staged files: %v", err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("staged files were not removed: %v", tempFiles)
	}
}

func TestCheckOneRetriesFailedNotification(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	blockedNotifyDir := filepath.Join(t.TempDir(), "notify")
	if err := os.WriteFile(blockedNotifyDir, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("create notification blocker: %v", err)
	}
	paths.notify = filepath.Join(blockedNotifyDir, "cert-updated-ecdsa")
	state := &certState{}
	store := newStatusStore([]algorithm{algorithmECDSA})
	const hostname = "host.example.test"

	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		state,
		store,
		hostname,
		completeDiscovery(nil, ""),
	); err == nil {
		t.Fatal("initial check succeeded despite blocked notification path")
	}
	if !state.notificationPending {
		t.Fatal("failed notification was not recorded as pending")
	}
	issued := loadTestCertificate(t, paths.cert)

	if err := os.Remove(blockedNotifyDir); err != nil {
		t.Fatalf("remove notification blocker: %v", err)
	}
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		state,
		store,
		hostname,
		completeDiscovery(nil, ""),
	); err != nil {
		t.Fatalf("retry notification: %v", err)
	}
	if state.notificationPending {
		t.Fatal("notification remained pending after successful retry")
	}
	if _, err := os.Stat(paths.notify); err != nil {
		t.Fatalf("notification file was not created: %v", err)
	}
	afterRetry := loadTestCertificate(t, paths.cert)
	if issued.SerialNumber.Cmp(afterRetry.SerialNumber) != 0 {
		t.Fatal("certificate was unnecessarily reissued while retrying notification")
	}
}

func TestRunExitsCleanlyWhenShutDownBeforeTheFirstCheck(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	cfg.algorithms = []algorithm{algorithmECDSA}
	cfg.pollInterval = time.Hour
	cfg.maxRetries = defaultMaxRetries
	cfg.httpAddr = ""

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// main treats context.Canceled as a clean exit, so this is the difference
	// between exit 0 and a unit reported as failed.
	if err := run(ctx, cfg, logger); !errors.Is(err, context.Canceled) {
		t.Fatalf("run during shutdown = %v, want context.Canceled", err)
	}
	if fileExists(paths.cert) || fileExists(paths.key) {
		t.Fatal("a certificate was issued while shutting down")
	}
	if fileExists(paths.notify) {
		t.Fatal("dependent services were notified while shutting down")
	}
}

func TestCheckAllStopsIssuingWhenShuttingDown(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	cfg.algorithms = []algorithm{algorithmECDSA}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	states := map[algorithm]*certState{algorithmECDSA: {}}
	if _, err := checkAll(ctx, cfg, logger, states, newStatusStore(cfg.algorithms)); !errors.Is(err, context.Canceled) {
		t.Fatalf("checkAll during shutdown = %v, want context.Canceled", err)
	}
	if fileExists(paths.cert) || fileExists(paths.key) {
		t.Fatal("a certificate was issued while shutting down")
	}
	// Touching the notification file restarts every dependent service, which
	// is the last thing that should happen on the way out.
	if fileExists(paths.notify) {
		t.Fatal("dependent services were notified while shutting down")
	}
}

func TestCheckOneDoesNotIssueWhenShuttingDown(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := checkOne(
		ctx,
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		"host.example.test",
		completeDiscovery(nil, ""),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("checkOne during shutdown = %v, want context.Canceled", err)
	}
	if fileExists(paths.cert) || fileExists(paths.key) {
		t.Fatal("a certificate was issued while shutting down")
	}
	if fileExists(paths.notify) {
		t.Fatal("dependent services were notified while shutting down")
	}
}

func TestCheckOneRecoversMissedNotificationAfterRestart(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, certificateIPAddresses(nil, "", nil)); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	issued := loadTestCertificate(t, paths.cert)

	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		hostname,
		completeDiscovery(nil, ""),
	); err != nil {
		t.Fatalf("recover notification after restart: %v", err)
	}
	if _, err := os.Stat(paths.notify); err != nil {
		t.Fatalf("notification file was not created: %v", err)
	}
	afterRecovery := loadTestCertificate(t, paths.cert)
	if issued.SerialNumber.Cmp(afterRecovery.SerialNumber) != 0 {
		t.Fatal("certificate was unnecessarily reissued while recovering notification")
	}
}

func TestCheckOneReissuesForIPSANChangesAfterRestart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		internalIP  bool
		externalIP  bool
		oldInternal []string
		newInternal []string
		oldExternal string
		newExternal string
	}{
		{
			name:        "internal IP changed",
			internalIP:  true,
			oldInternal: []string{"192.0.2.10"},
			newInternal: []string{"192.0.2.20"},
		},
		{
			name:        "internal IP removed",
			internalIP:  true,
			oldInternal: []string{"192.0.2.10", "192.0.2.20"},
			newInternal: []string{"192.0.2.20"},
		},
		{
			name:        "external IP changed",
			externalIP:  true,
			oldExternal: "198.51.100.10",
			newExternal: "198.51.100.20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, paths, logger := newTestCertificateConfig(t, tt.internalIP, tt.externalIP)
			const hostname = "host.example.test"
			if err := issueCert(
				logger,
				cfg,
				algorithmECDSA,
				paths,
				hostname,
				certificateIPAddresses(tt.oldInternal, tt.oldExternal, nil),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}

			before := loadTestCertificate(t, paths.cert)
			stateAfterRestart := &certState{}
			store := newStatusStore([]algorithm{algorithmECDSA})
			if err := checkOne(
				t.Context(),
				logger,
				cfg,
				algorithmECDSA,
				paths,
				stateAfterRestart,
				store,
				hostname,
				completeDiscovery(tt.newInternal, tt.newExternal),
			); err != nil {
				t.Fatalf("check certificate: %v", err)
			}

			after := loadTestCertificate(t, paths.cert)
			if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
				t.Fatal("certificate was not reissued after its IP SANs changed")
			}
			desiredIPs := certificateIPAddresses(tt.newInternal, tt.newExternal, nil)
			if !ipAddressSetsEqual(after.IPAddresses, desiredIPs) {
				t.Fatalf(
					"certificate IP SANs = %v, want %v",
					ipAddressesToStrings(after.IPAddresses),
					ipAddressesToStrings(desiredIPs),
				)
			}
		})
	}
}

func TestCheckOneKeepsCertificateWhenIncompleteDiscoveryMatchesIt(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, true)
	const hostname = "host.example.test"
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		certificateIPAddresses(nil, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	before := loadTestCertificate(t, paths.cert)
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		hostname,
		addressDiscovery{internalComplete: true},
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	after := loadTestCertificate(t, paths.cert)
	if before.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Fatal("certificate was reissued although it already held every confirmable address")
	}
}

func TestCheckOneRetainsIPSANsWhenReissuingWithIncompleteDiscovery(t *testing.T) {
	t.Parallel()

	const (
		previousHostname = "old.example.test"
		currentHostname  = "host.example.test"
		externalIP       = "198.51.100.10"
	)
	internalIPs := []string{"192.0.2.10", "192.0.2.11"}

	tests := []struct {
		name           string
		issuedHostname string
		issuedLifetime time.Duration
		checkLifetime  time.Duration
		wantReason     string
	}{
		{
			name:           "hostname changed",
			issuedHostname: previousHostname,
			issuedLifetime: 24 * time.Hour,
			checkLifetime:  24 * time.Hour,
			wantReason:     "hostname changed",
		},
		{
			name:           "lifetime changed",
			issuedHostname: currentHostname,
			issuedLifetime: 24 * time.Hour,
			checkLifetime:  12 * time.Hour,
			wantReason:     "lifetime changed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, paths, logger, logged := newTestCertificateConfigWithLog(t, true, true)
			cfg.lifetime = tt.issuedLifetime
			if err := issueCert(
				logger,
				cfg,
				algorithmECDSA,
				paths,
				tt.issuedHostname,
				certificateIPAddresses(internalIPs, externalIP, nil),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}

			before := loadTestCertificate(t, paths.cert)
			cfg.lifetime = tt.checkLifetime
			if err := checkOne(
				t.Context(),
				logger,
				cfg,
				algorithmECDSA,
				paths,
				&certState{},
				newStatusStore([]algorithm{algorithmECDSA}),
				currentHostname,
				addressDiscovery{internalIPs: internalIPs, internalComplete: true},
			); err != nil {
				t.Fatalf("check certificate: %v", err)
			}

			after := loadTestCertificate(t, paths.cert)
			if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
				t.Fatal("certificate was not reissued")
			}
			if want := `reason="` + tt.wantReason + `"`; !strings.Contains(logged.String(), want) {
				t.Fatalf("certificate was reissued for another reason than %s:\n%s", tt.wantReason, logged)
			}
			if !ipAddressSetsEqual(after.IPAddresses, before.IPAddresses) {
				t.Fatalf(
					"reissued certificate dropped IP SANs: got %v, want %v",
					ipAddressesToStrings(after.IPAddresses),
					ipAddressesToStrings(before.IPAddresses),
				)
			}
		})
	}
}

func TestCheckOneKeepsDiscoveredAndRetainedIPSANsWhenDiscoveryIsPartial(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		"old.example.test",
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	// External IP discovery failed this cycle, but a new internal address was
	// found. The reissued certificate must carry both.
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		"host.example.test",
		addressDiscovery{internalIPs: []string{"192.0.2.20"}, internalComplete: true},
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	after := loadTestCertificate(t, paths.cert)
	want := certificateIPAddresses(
		[]string{"192.0.2.10", "192.0.2.20"},
		"198.51.100.10",
		nil,
	)
	if !ipAddressSetsEqual(after.IPAddresses, want) {
		t.Fatalf(
			"certificate IP SANs = %v, want %v",
			ipAddressesToStrings(after.IPAddresses),
			ipAddressesToStrings(want),
		)
	}
}

func TestCheckOneDetectsInternalIPChangeWhileExternalDetectionFails(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	const hostname = "host.example.test"
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	before := loadTestCertificate(t, paths.cert)

	// Interface enumeration is authoritative and reports a new address. External
	// detection is failing, but that must not stop the change being acted on.
	st := &certState{internalIPs: []string{"192.0.2.10"}}
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		st,
		newStatusStore([]algorithm{algorithmECDSA}),
		hostname,
		addressDiscovery{internalIPs: []string{"192.0.2.20"}, internalComplete: true},
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	after := loadTestCertificate(t, paths.cert)
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
		t.Fatal("certificate was not reissued after an internal IP change")
	}
	want := certificateIPAddresses([]string{"192.0.2.20"}, "198.51.100.10", nil)
	if !ipAddressSetsEqual(after.IPAddresses, want) {
		t.Fatalf(
			"certificate IP SANs = %v, want %v",
			ipAddressesToStrings(after.IPAddresses),
			ipAddressesToStrings(want),
		)
	}
}

func TestCheckOneReissuesOnceWhenDiscoveryStaysIncomplete(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	const hostname = "host.example.test"
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	st := &certState{internalIPs: []string{"192.0.2.10"}}
	store := newStatusStore([]algorithm{algorithmECDSA})
	d := addressDiscovery{internalIPs: []string{"192.0.2.20"}, internalComplete: true}

	check := func(cycle string) *x509.Certificate {
		t.Helper()
		if err := checkOne(t.Context(), logger, cfg, algorithmECDSA, paths, st, store, hostname, d); err != nil {
			t.Fatalf("%s: %v", cycle, err)
		}
		return loadTestCertificate(t, paths.cert)
	}

	// The set issued under incomplete discovery must be stable, or every
	// subsequent poll reissues the certificate and restarts dependent services.
	first := check("first cycle")
	second := check("second cycle")
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf(
			"certificate reissued again on an unchanged cycle: %v then %v",
			ipAddressesToStrings(first.IPAddresses),
			ipAddressesToStrings(second.IPAddresses),
		)
	}
}

func TestCheckOneRemainsStableWhenInterfaceEnumerationFails(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	const hostname = "host.example.test"
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	// Interface enumeration failed, so no internal address can be confirmed or
	// contradicted, but the external address is known and has changed.
	st := &certState{internalIPs: []string{"192.0.2.10"}}
	store := newStatusStore([]algorithm{algorithmECDSA})
	d := addressDiscovery{externalIP: "198.51.100.20", externalComplete: true}

	check := func(cycle string) *x509.Certificate {
		t.Helper()
		if err := checkOne(t.Context(), logger, cfg, algorithmECDSA, paths, st, store, hostname, d); err != nil {
			t.Fatalf("%s: %v", cycle, err)
		}
		return loadTestCertificate(t, paths.cert)
	}

	first := check("first cycle")
	// The internal addresses could not be confirmed, so they are kept, and the
	// previous external address cannot be told apart from them. Both externals
	// are therefore present until enumeration recovers.
	want := certificateIPAddresses(
		[]string{"192.0.2.10", "198.51.100.10"},
		"198.51.100.20",
		nil,
	)
	if !ipAddressSetsEqual(first.IPAddresses, want) {
		t.Fatalf(
			"certificate IP SANs = %v, want %v",
			ipAddressesToStrings(first.IPAddresses),
			ipAddressesToStrings(want),
		)
	}

	second := check("second cycle")
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatal("certificate reissued again on an unchanged cycle")
	}
}

func TestCheckOnePrunesDepartedInternalIPWhileExternalDetectionFails(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		"old.example.test",
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	// An earlier cycle of this process observed 192.0.2.10 on an interface.
	// Enumeration now reports 192.0.2.20 instead, so the old address is gone
	// rather than unconfirmed — but external detection is still failing, so the
	// external SAN cannot be reconfirmed and must be kept.
	st := &certState{internalIPs: []string{"192.0.2.10"}}
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		st,
		newStatusStore([]algorithm{algorithmECDSA}),
		"new.example.test",
		addressDiscovery{internalIPs: []string{"192.0.2.20"}, internalComplete: true},
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	after := loadTestCertificate(t, paths.cert)
	want := certificateIPAddresses([]string{"192.0.2.20"}, "198.51.100.10", nil)
	if !ipAddressSetsEqual(after.IPAddresses, want) {
		t.Fatalf(
			"certificate IP SANs = %v, want %v",
			ipAddressesToStrings(after.IPAddresses),
			ipAddressesToStrings(want),
		)
	}
}

func TestCheckOneIssuesMissingCertificateDespiteIncompleteDiscovery(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, true, true)
	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		"host.example.test",
		addressDiscovery{internalIPs: []string{"192.0.2.10"}, internalComplete: true},
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	issued := loadTestCertificate(t, paths.cert)
	want := certificateIPAddresses([]string{"192.0.2.10"}, "", nil)
	if !ipAddressSetsEqual(issued.IPAddresses, want) {
		t.Fatalf(
			"certificate IP SANs = %v, want %v",
			ipAddressesToStrings(issued.IPAddresses),
			ipAddressesToStrings(want),
		)
	}
}

func TestCheckOneReissuesWhenConfiguredLifetimeChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		issued   time.Duration
		modified time.Duration
	}{
		{name: "lifetime shortened", issued: 24 * time.Hour, modified: time.Hour},
		{name: "lifetime lengthened", issued: time.Hour, modified: 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, paths, logger := newTestCertificateConfig(t, false, false)
			const hostname = "host.example.test"
			cfg.lifetime = tt.issued
			if err := issueCert(
				logger,
				cfg,
				algorithmECDSA,
				paths,
				hostname,
				certificateIPAddresses(nil, "", nil),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}
			before := loadTestCertificate(t, paths.cert)

			cfg.lifetime = tt.modified
			if err := checkOne(
				t.Context(),
				logger,
				cfg,
				algorithmECDSA,
				paths,
				&certState{},
				newStatusStore([]algorithm{algorithmECDSA}),
				hostname,
				completeDiscovery(nil, ""),
			); err != nil {
				t.Fatalf("check certificate: %v", err)
			}

			after := loadTestCertificate(t, paths.cert)
			if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
				t.Fatal("certificate was not reissued after the configured lifetime changed")
			}
			if span := after.NotAfter.Sub(after.NotBefore); span != tt.modified {
				t.Fatalf("reissued certificate lifetime = %s, want %s", span, tt.modified)
			}
		})
	}
}

func TestCheckOneReissuesOnceAfterLifetimeChange(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	cfg.lifetime = 24 * time.Hour
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		certificateIPAddresses(nil, "", nil),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	cfg.lifetime = 12 * time.Hour
	st := &certState{}
	store := newStatusStore([]algorithm{algorithmECDSA})
	check := func(cycle string) *x509.Certificate {
		t.Helper()
		if err := checkOne(
			t.Context(),
			logger, cfg, algorithmECDSA, paths, st, store, hostname, completeDiscovery(nil, ""),
		); err != nil {
			t.Fatalf("%s: %v", cycle, err)
		}
		return loadTestCertificate(t, paths.cert)
	}

	// The reissued certificate must record the configured lifetime exactly, or
	// the comparison stays unsatisfied and every poll reissues it again.
	first := check("first cycle")
	second := check("second cycle")
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf(
			"certificate reissued again on an unchanged cycle: lifetime recorded as %s, configured %s",
			first.NotAfter.Sub(first.NotBefore),
			cfg.lifetime,
		)
	}
}

func TestNeedsRenewal(t *testing.T) {
	t.Parallel()

	const span = 24 * time.Hour
	tests := []struct {
		name      string
		remaining time.Duration
		want      bool
	}{
		{name: "freshly issued", remaining: span, want: false},
		{name: "above threshold", remaining: 9 * time.Hour, want: false},
		{name: "below threshold", remaining: 7 * time.Hour, want: true},
		{name: "already expired", remaining: -time.Hour, want: true},
	}

	// The exact threshold is deliberately untested: remaining is measured
	// against the wall clock inside needsRenewal, so a case built to sit on the
	// boundary always lands marginally below it by the time the call is made.

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			notAfter := time.Now().Add(tt.remaining)
			cert := &x509.Certificate{NotBefore: notAfter.Add(-span), NotAfter: notAfter}
			if got := needsRenewal(cert, renewThreshold); got != tt.want {
				t.Fatalf("needsRenewal with %s of %s remaining = %t, want %t",
					tt.remaining, span, got, tt.want)
			}
		})
	}
}

// withFailingExternalIPProviders points external IP detection at a URL that
// fails when the request is built, so the retry loop runs without touching the
// network and without waiting for a timeout.
func withFailingExternalIPProviders(t *testing.T) {
	t.Helper()

	restore := externalIPProviders
	t.Cleanup(func() { externalIPProviders = restore })
	externalIPProviders = []string{"://invalid"}
}

// externalIPProvider starts a stand-in provider returning the given status and
// body, and returns its URL.
func externalIPProvider(t *testing.T, status int, body string) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func useExternalIPProviders(t *testing.T, urls ...string) {
	t.Helper()

	restore := externalIPProviders
	t.Cleanup(func() { externalIPProviders = restore })
	externalIPProviders = urls
}

func TestGetExternalIPIgnoresUnsuccessfulResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		// The body of an error response is not an answer, however much it may
		// look like one. A proxy or captive portal answering 429 or 503 with
		// something address-shaped is reporting its own state, not this host's.
		{name: "rate limited", status: http.StatusTooManyRequests, body: "203.0.113.5"},
		{name: "server error", status: http.StatusInternalServerError, body: "203.0.113.5"},
		{name: "not found", status: http.StatusNotFound, body: "203.0.113.5"},
		{name: "redirect body", status: http.StatusBadGateway, body: "203.0.113.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useExternalIPProviders(t, externalIPProvider(t, tt.status, tt.body))

			ip, err := getExternalIP(t.Context(), slog.New(slog.DiscardHandler))
			if err == nil {
				t.Fatalf("getExternalIP accepted %s %q and returned %q", tt.name, tt.body, ip)
			}
		})
	}
}

func TestGetExternalIPFallsThroughToASuccessfulProvider(t *testing.T) {
	useExternalIPProviders(t,
		externalIPProvider(t, http.StatusTooManyRequests, "203.0.113.5"),
		externalIPProvider(t, http.StatusOK, "198.51.100.20\n"),
	)

	ip, err := getExternalIP(t.Context(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("getExternalIP: %v", err)
	}
	if ip != "198.51.100.20" {
		t.Fatalf("getExternalIP = %q, want the address from the provider that answered 200", ip)
	}
}

func TestGetExternalIPAcceptsASuccessfulResponse(t *testing.T) {
	useExternalIPProviders(t, externalIPProvider(t, http.StatusOK, "  203.0.113.5  "))

	ip, err := getExternalIP(t.Context(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("getExternalIP: %v", err)
	}
	if ip != "203.0.113.5" {
		t.Fatalf("getExternalIP = %q, want 203.0.113.5", ip)
	}
}

func TestGetExternalIPWithRetryDoesNotWaitAfterTheFinalAttempt(t *testing.T) {
	withFailingExternalIPProviders(t)

	start := time.Now()
	_, err := getExternalIPWithRetry(context.Background(), 1, slog.New(slog.DiscardHandler))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("getExternalIPWithRetry succeeded against a failing provider")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("a single attempt took %s; the delay after the final attempt is never used", elapsed)
	}
}

func TestGetExternalIPWithRetryWaitsBetweenAttempts(t *testing.T) {
	withFailingExternalIPProviders(t)

	// Two attempts wait once, between them: the first delay of one second and
	// no more. Guards against dropping the wait altogether while removing the
	// unused one that followed the last attempt.
	start := time.Now()
	_, err := getExternalIPWithRetry(context.Background(), 2, slog.New(slog.DiscardHandler))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("getExternalIPWithRetry succeeded against a failing provider")
	}
	if elapsed < time.Second {
		t.Fatalf("two attempts took %s; they did not wait between attempts", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("two attempts took %s; more than one delay was waited", elapsed)
	}
}

func TestSplitList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty", input: "", want: nil},
		{name: "single", input: "eth0", want: []string{"eth0"}},
		{name: "several", input: "eth0,eth1", want: []string{"eth0", "eth1"}},
		{name: "spaces around entries", input: " eth0 , eth1 ", want: []string{"eth0", "eth1"}},
		{name: "trailing comma", input: "eth0,", want: []string{"eth0"}},
		{name: "only separators", input: " , ", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := splitList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitList(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("splitList(%q) = %#v, want %#v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestSelectedInterfaces(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)

	if got := selectedInterfaces(t.Context(), []string{interfacesAll}, logger); got != nil {
		t.Fatalf("selecting %q restricted the interfaces to %v, want every one", interfacesAll, got)
	}

	got := selectedInterfaces(t.Context(), []string{"eth0", "eth1"}, logger)
	if len(got) != 2 {
		t.Fatalf("named selection = %v, want two entries", got)
	}
	for _, name := range []string{"eth0", "eth1"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("named selection = %v, want it to contain %q", got, name)
		}
	}
}

func TestGetInternalIPsSelectionNarrowsTheResult(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)

	all, err := getInternalIPs(t.Context(), []string{interfacesAll}, logger)
	if err != nil {
		t.Fatalf("enumerating every interface: %v", err)
	}
	if len(all) == 0 {
		t.Skip("host has no usable IPv4 address to select between")
	}

	// Following the default route can only ever return a subset of what every
	// interface offers, whichever interface this host actually routes through.
	viaDefaultRoute, err := getInternalIPs(t.Context(), nil, logger)
	if err != nil {
		t.Fatalf("following the default route: %v", err)
	}
	for _, ip := range viaDefaultRoute {
		if !slices.Contains(all, ip) {
			t.Fatalf("default route produced %s, which is not among %v", ip, all)
		}
	}

	// Naming the default route explicitly must mean the same as leaving the
	// setting empty, not "an interface called default-route".
	named, err := getInternalIPs(t.Context(), []string{interfacesDefaultRoute}, logger)
	if err != nil {
		t.Fatalf("naming the default route: %v", err)
	}
	if len(named) != len(viaDefaultRoute) {
		t.Fatalf("%q produced %v, want the same as an empty selection, %v",
			interfacesDefaultRoute, named, viaDefaultRoute)
	}
	for i := range named {
		if named[i] != viaDefaultRoute[i] {
			t.Fatalf("%q produced %v, want the same as an empty selection, %v",
				interfacesDefaultRoute, named, viaDefaultRoute)
		}
	}

	// An interface that does not exist contributes nothing, and is reported
	// rather than failing the poll: interfaces can appear later.
	none, err := getInternalIPs(t.Context(), []string{"certd-absent0"}, logger)
	if err != nil {
		t.Fatalf("selecting an absent interface: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("absent interface produced %v, want nothing", none)
	}
}

func TestDefaultRouteInterfaceNamesAnInterfaceThatExists(t *testing.T) {
	t.Parallel()

	name, err := defaultRouteInterface(t.Context())
	if err != nil {
		t.Skipf("host has no default route: %v", err)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("default route named interface %q, which does not exist: %v", name, err)
	}
}

func TestCheckOneCertifiesConfiguredExtraSANs(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	// A floating address this node does not hold, as on the standby member of
	// a VRRP pair, plus the service name clients actually connect to.
	cfg.extraIPs = []net.IP{net.ParseIP("10.0.0.100")}
	cfg.extraDNS = []string{"vip.example.test"}

	if err := checkOne(
		t.Context(),
		logger,
		cfg,
		algorithmECDSA,
		paths,
		&certState{},
		newStatusStore([]algorithm{algorithmECDSA}),
		"host.example.test",
		completeDiscovery(nil, ""),
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	cert := loadTestCertificate(t, paths.cert)
	if !ipAddressSetsEqual(cert.IPAddresses, certificateIPAddresses(nil, "", cfg.extraIPs)) {
		t.Fatalf("certificate IP SANs = %v, want the configured address included",
			ipAddressesToStrings(cert.IPAddresses))
	}
	if !slices.Contains(cert.DNSNames, "vip.example.test") {
		t.Fatalf("certificate DNS SANs = %v, want the configured name included", cert.DNSNames)
	}
	if !slices.Contains(cert.DNSNames, "host.example.test") {
		t.Fatalf("certificate DNS SANs = %v, want the hostname retained", cert.DNSNames)
	}
}

func TestCheckOneReissuesWhenExtraSANsChange(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	st := &certState{}
	store := newStatusStore([]algorithm{algorithmECDSA})
	check := func(stage string) *x509.Certificate {
		t.Helper()
		if err := checkOne(
			t.Context(),
			logger, cfg, algorithmECDSA, paths, st, store, hostname, completeDiscovery(nil, ""),
		); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		return loadTestCertificate(t, paths.cert)
	}

	before := check("initial issuance")

	cfg.extraDNS = []string{"vip.example.test"}
	after := check("after adding a name")
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
		t.Fatal("certificate was not reissued after a DNS SAN was configured")
	}
	if !slices.Contains(after.DNSNames, "vip.example.test") {
		t.Fatalf("certificate DNS SANs = %v, want the new name", after.DNSNames)
	}

	// And settles: an unchanged configuration must not reissue every poll.
	again := check("second poll")
	if after.SerialNumber.Cmp(again.SerialNumber) != 0 {
		t.Fatal("certificate reissued again on an unchanged cycle")
	}

	cfg.extraDNS = nil
	removed := check("after removing the name")
	if again.SerialNumber.Cmp(removed.SerialNumber) == 0 {
		t.Fatal("certificate was not reissued after a DNS SAN was removed")
	}
	if slices.Contains(removed.DNSNames, "vip.example.test") {
		t.Fatalf("certificate DNS SANs = %v, want the removed name gone", removed.DNSNames)
	}
}

func TestClassifyExtraSANs(t *testing.T) {
	t.Parallel()

	ips, names, err := classifyExtraSANs([]string{
		"10.0.0.100", "vip.example.test", "2001:db8::1", "*.apps.example.test", "host.example.test.",
	})
	if err != nil {
		t.Fatalf("classifying valid entries: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("addresses = %v, want two", ipAddressesToStrings(ips))
	}
	if len(names) != 3 {
		t.Fatalf("names = %v, want three", names)
	}
}

func TestClassifyExtraSANsRejectsMalformedEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry string
	}{
		// Numeric-looking entries are mistyped addresses, not host names. Left
		// to DNS validation "10.0.0.256" is a syntactically fine name, and
		// would be certified as one.
		{name: "octet out of range", entry: "10.0.0.256"},
		{name: "too many octets", entry: "10.0.0.1.5"},
		{name: "truncated IPv6", entry: "2001:db8:::1"},
		{name: "empty label", entry: "host..example.test"},
		{name: "label starts with a dash", entry: "-host.example.test"},
		{name: "label ends with a dash", entry: "host-.example.test"},
		{name: "space in name", entry: "host .example.test"},
		{name: "underscore in name", entry: "host_name.example.test"},
		{name: "url rather than a name", entry: "https://host.example.test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if ips, names, err := classifyExtraSANs([]string{tt.entry}); err == nil {
				t.Fatalf("classifyExtraSANs(%q) = %v, %v, want an error",
					tt.entry, ipAddressesToStrings(ips), names)
			}
		})
	}
}

func TestUsableInternalIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "private address", ip: "192.168.1.10", want: true},
		{name: "public address", ip: "203.0.113.7", want: true},
		{name: "container bridge address", ip: "172.17.0.1", want: true},
		{name: "loopback", ip: "127.0.0.1", want: false},
		// APIPA. It appears precisely when DHCP has failed and disappears when
		// it recovers, so including it re-issues the certificate each way while
		// naming an address nothing can be reached on.
		{name: "link-local", ip: "169.254.23.45", want: false},
		{name: "link-local at the edge of the range", ip: "169.254.255.255", want: false},
		{name: "just below the link-local range", ip: "169.253.255.255", want: true},
		{name: "IPv6", ip: "2001:db8::1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("test address %q does not parse", tt.ip)
			}
			if got := usableInternalIP(ip); got != tt.want {
				t.Fatalf("usableInternalIP(%s) = %t, want %t", tt.ip, got, tt.want)
			}
		})
	}

	if usableInternalIP(nil) {
		t.Fatal("usableInternalIP(nil) = true, want false")
	}
}

func TestBackoffStopsDoublingAtTheCap(t *testing.T) {
	t.Parallel()

	var got []time.Duration
	backoff := time.Second
	for range 8 {
		got = append(got, backoff)
		backoff = nextBackoff(backoff)
	}

	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 16 * time.Second, 16 * time.Second, 16 * time.Second,
	}
	if len(got) != len(want) {
		t.Fatalf("backoff schedule = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff schedule = %v, want %v", got, want)
		}
	}
}

func TestRetryBackoffStaysBoundedAtMaxRetries(t *testing.T) {
	t.Parallel()

	// Without a cap the delay doubles with every retry, so the retry count buys
	// exponential time: at the permitted maximum the last sleep alone would run
	// for days, and because the first check gates the systemd readiness
	// notification, it would hold up startup for just as long.
	total := retryBackoffBudget(maxRetries)
	if limit := 5 * time.Minute; total > limit {
		t.Fatalf("worst-case backoff over %d retries = %s, want at most %s", maxRetries, total, limit)
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input time.Duration
		want  string
	}{
		{name: "whole years", input: 25 * 8760 * time.Hour, want: "25y"},
		{name: "one year", input: 8760 * time.Hour, want: "1y"},
		{name: "whole days", input: 24 * time.Hour, want: "1d"},
		{name: "whole hours", input: time.Hour, want: "1h"},
		{name: "whole minutes", input: time.Minute, want: "1m"},
		{name: "sub-minute precision", input: 90500 * time.Millisecond, want: "1m30.5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := humanDuration(tt.input)
			if got != tt.want {
				t.Fatalf("humanDuration(%s) = %q, want %q", tt.input, got, tt.want)
			}
			// Whatever it prints must read back as the same duration, since the
			// value is shown to operators as something to put in the config.
			parsed, err := parseDuration(got)
			if err != nil {
				t.Fatalf("humanDuration(%s) = %q, which does not parse: %v", tt.input, got, err)
			}
			if parsed != tt.input {
				t.Fatalf("humanDuration(%s) = %q, which parses back as %s", tt.input, got, parsed)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{name: "years", input: "1y", want: 8760 * time.Hour},
		{name: "weeks", input: "2w", want: 336 * time.Hour},
		{name: "days", input: "90d", want: 2160 * time.Hour},
		{name: "combined", input: "1y30d", want: 9480 * time.Hour},
		{name: "three units", input: "2w3d12h", want: 420 * time.Hour},
		{name: "standard unit only", input: "90m", want: 90 * time.Minute},
		{name: "extended and standard", input: "1d12h", want: 36 * time.Hour},
		{name: "zero", input: "0", want: 0},
		{name: "largest representable", input: "292y", want: 292 * 8760 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDuration(tt.input)
			if err != nil {
				t.Fatalf("parseDuration(%q) = %v, want %s", tt.input, err, tt.want)
			}
			if got != tt.want {
				t.Fatalf("parseDuration(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseDurationRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "not a duration", input: "soon"},
		{name: "unknown unit", input: "5f"},
		// Each of these silently produced a wrong duration rather than an
		// error: the count overflowed its multiplication, or the digits did
		// not fit in an int at all.
		{name: "count overflows the unit", input: "2000000y"},
		{name: "count exceeds int64", input: "1h99999999999999999999d"},
		{name: "beyond the largest duration", input: "293y"},
		{name: "sum overflows", input: "292y292y"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDuration(tt.input)
			if err == nil {
				t.Fatalf("parseDuration(%q) = %s, want an error", tt.input, got)
			}
			if got != 0 {
				t.Fatalf("parseDuration(%q) returned %s alongside its error, want 0", tt.input, got)
			}
		})
	}
}

func TestREADMEDocumentsActualDefaults(t *testing.T) {
	t.Parallel()

	documented := readREADMEDefaults(t)

	literals := []struct {
		env  string
		want string
	}{
		{"CERTD_ECDSA", strconv.FormatBool(defaultECDSA)},
		{"CERTD_ED25519", strconv.FormatBool(defaultEd25519)},
		{"CERTD_RSA", strconv.FormatBool(defaultRSA)},
		{"CERTD_CERT_DIR", defaultCertDir},
		{"CERTD_NOTIFY_DIR", defaultNotifyDir},
		{"CERTD_INTERNAL_IP", strconv.FormatBool(defaultInternalIP)},
		{"CERTD_EXTERNAL_IP", strconv.FormatBool(defaultExternalIP)},
		{"CERTD_MAX_RETRIES", strconv.Itoa(defaultMaxRetries)},
		{"CERTD_HTTP_ADDR", defaultHTTPAddr},
	}
	for _, tt := range literals {
		got, ok := documented[tt.env]
		if !ok {
			t.Errorf("%s has no row in the configuration reference", tt.env)
			continue
		}
		if got != tt.want {
			t.Errorf("%s documented default = %q, code default = %q", tt.env, got, tt.want)
		}
	}

	// Durations are compared by value, so any equivalent spelling passes.
	durations := []struct {
		env  string
		want time.Duration
	}{
		{"CERTD_LIFETIME", defaultLifetime},
		{"CERTD_POLL_INTERVAL", defaultPollInterval},
	}
	for _, tt := range durations {
		got, ok := documented[tt.env]
		if !ok {
			t.Errorf("%s has no row in the configuration reference", tt.env)
			continue
		}
		parsed, err := parseDuration(got)
		if err != nil {
			t.Errorf("%s documented default %q does not parse: %v", tt.env, got, err)
			continue
		}
		if parsed != tt.want {
			t.Errorf("%s documented default = %q (%s), code default = %s", tt.env, got, parsed, tt.want)
		}
	}
}

// readREADMEDefaults returns the default documented for every CERTD_* variable
// in the configuration reference table.
func readREADMEDefaults(t *testing.T) map[string]string {
	t.Helper()

	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}

	defaults := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| `CERTD_") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 3 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[0]), "`")
		defaults[name] = strings.Trim(strings.TrimSpace(cells[2]), "`")
	}
	if len(defaults) == 0 {
		t.Fatal("no CERTD_* rows found in the configuration reference table")
	}
	return defaults
}

func TestIPAddressSetsEqualIgnoresOrderAndDuplicates(t *testing.T) {
	t.Parallel()

	a := certificateIPAddresses([]string{"192.0.2.10", "192.0.2.20"}, "198.51.100.10", nil)
	b := certificateIPAddresses(
		[]string{"192.0.2.20", "192.0.2.10", "192.0.2.10"},
		"198.51.100.10",
		nil,
	)
	if !ipAddressSetsEqual(a, b) {
		t.Fatalf("IP sets differ: %v and %v", ipAddressesToStrings(a), ipAddressesToStrings(b))
	}
}

// completeDiscovery describes a cycle in which every enabled source answered.
func completeDiscovery(internalIPs []string, externalIP string) addressDiscovery {
	return addressDiscovery{
		internalIPs:      internalIPs,
		internalComplete: true,
		externalIP:       externalIP,
		externalComplete: true,
	}
}

func newTestCertificateConfig(
	t *testing.T,
	internalIP bool,
	externalIP bool,
) (*config, certPaths, *slog.Logger) {
	t.Helper()

	cfg, paths, logger, _ := newTestCertificateConfigWithLog(t, internalIP, externalIP)
	return cfg, paths, logger
}

// newTestCertificateConfigWithLog additionally returns the captured log output,
// so a test can assert which branch of checkOne issued a certificate rather than
// only that one was issued.
func newTestCertificateConfigWithLog(
	t *testing.T,
	internalIP bool,
	externalIP bool,
) (*config, certPaths, *slog.Logger, *bytes.Buffer) {
	t.Helper()

	baseDir := t.TempDir()
	cfg := &config{
		lifetime:   24 * time.Hour,
		certDir:    baseDir,
		notifyDir:  baseDir,
		internalIP: internalIP,
		externalIP: externalIP,
	}
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	return cfg, certPathsForAlgorithm(cfg, algorithmECDSA), logger, &logged
}

func loadTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	cert, err := loadCert(path)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	return cert
}
