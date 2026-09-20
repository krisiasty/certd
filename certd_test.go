// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Krzysztof Ciepłucha

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
			wantError: "poll interval must be at least",
		},
		{
			name: "negative poll interval",
			configure: func(cfg *config) {
				cfg.pollInterval = -time.Second
			},
			wantError: "poll interval must be at least",
		},
		{
			name: "poll interval below minimum",
			configure: func(cfg *config) {
				cfg.pollInterval = time.Second
			},
			wantError: "poll interval must be at least",
		},
		{
			name: "zero certificate lifetime",
			configure: func(cfg *config) {
				cfg.lifetime = 0
			},
			wantError: "certificate lifetime must be at least",
		},
		{
			name: "certificate lifetime below minimum",
			configure: func(cfg *config) {
				cfg.lifetime = 30 * time.Minute
			},
			wantError: "certificate lifetime must be at least",
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
			wantError: "maximum retries must be positive",
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
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, certificateIPAddresses(nil, "")); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	initial := loadTestCertificate(t, paths.cert)

	_, replacementKey, err := generateCert(algorithmECDSA, cfg, hostname, certificateIPAddresses(nil, ""))
	if err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	if err := os.WriteFile(paths.key, replacementKey, 0600); err != nil {
		t.Fatalf("replace private key: %v", err)
	}

	if err := checkOne(
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
	if err := issueCert(logger, cfg, algorithmEd25519, paths, hostname, certificateIPAddresses(nil, "")); err != nil {
		t.Fatalf("issue certificate with wrong algorithm: %v", err)
	}

	if err := checkOne(
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

	if err := issueCert(logger, cfg, algorithmECDSA, paths, "host.example.test", certificateIPAddresses(nil, "")); err != nil {
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

func TestCheckOneRecoversMissedNotificationAfterRestart(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, false)
	const hostname = "host.example.test"
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, certificateIPAddresses(nil, "")); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	issued := loadTestCertificate(t, paths.cert)

	if err := checkOne(
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
				certificateIPAddresses(tt.oldInternal, tt.oldExternal),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}

			before := loadTestCertificate(t, paths.cert)
			stateAfterRestart := &certState{}
			store := newStatusStore([]algorithm{algorithmECDSA})
			if err := checkOne(
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
			desiredIPs := certificateIPAddresses(tt.newInternal, tt.newExternal)
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
		certificateIPAddresses(nil, "198.51.100.10"),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	before := loadTestCertificate(t, paths.cert)
	if err := checkOne(
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
				certificateIPAddresses(internalIPs, externalIP),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}

			before := loadTestCertificate(t, paths.cert)
			cfg.lifetime = tt.checkLifetime
			if err := checkOne(
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
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10"),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	// External IP discovery failed this cycle, but a new internal address was
	// found. The reissued certificate must carry both.
	if err := checkOne(
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
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10"),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	before := loadTestCertificate(t, paths.cert)

	// Interface enumeration is authoritative and reports a new address. External
	// detection is failing, but that must not stop the change being acted on.
	st := &certState{internalIPs: []string{"192.0.2.10"}}
	if err := checkOne(
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
	want := certificateIPAddresses([]string{"192.0.2.20"}, "198.51.100.10")
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
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10"),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	st := &certState{internalIPs: []string{"192.0.2.10"}}
	store := newStatusStore([]algorithm{algorithmECDSA})
	d := addressDiscovery{internalIPs: []string{"192.0.2.20"}, internalComplete: true}

	check := func(cycle string) *x509.Certificate {
		t.Helper()
		if err := checkOne(logger, cfg, algorithmECDSA, paths, st, store, hostname, d); err != nil {
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
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10"),
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
		if err := checkOne(logger, cfg, algorithmECDSA, paths, st, store, hostname, d); err != nil {
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
		certificateIPAddresses([]string{"192.0.2.10"}, "198.51.100.10"),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	// An earlier cycle of this process observed 192.0.2.10 on an interface.
	// Enumeration now reports 192.0.2.20 instead, so the old address is gone
	// rather than unconfirmed — but external detection is still failing, so the
	// external SAN cannot be reconfirmed and must be kept.
	st := &certState{internalIPs: []string{"192.0.2.10"}}
	if err := checkOne(
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
	want := certificateIPAddresses([]string{"192.0.2.20"}, "198.51.100.10")
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
	want := certificateIPAddresses([]string{"192.0.2.10"}, "")
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
				certificateIPAddresses(nil, ""),
			); err != nil {
				t.Fatalf("issue initial certificate: %v", err)
			}
			before := loadTestCertificate(t, paths.cert)

			cfg.lifetime = tt.modified
			if err := checkOne(
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
		certificateIPAddresses(nil, ""),
	); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}

	cfg.lifetime = 12 * time.Hour
	st := &certState{}
	store := newStatusStore([]algorithm{algorithmECDSA})
	check := func(cycle string) *x509.Certificate {
		t.Helper()
		if err := checkOne(
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

	a := certificateIPAddresses([]string{"192.0.2.10", "192.0.2.20"}, "198.51.100.10")
	b := certificateIPAddresses(
		[]string{"192.0.2.20", "192.0.2.10", "192.0.2.10"},
		"198.51.100.10",
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
