// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Krzysztof Ciepłucha

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, nil, ""); err != nil {
		t.Fatalf("issue initial certificate: %v", err)
	}
	initial := loadTestCertificate(t, paths.cert)

	_, replacementKey, err := generateCert(algorithmECDSA, cfg, hostname, nil, "")
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
		nil,
		"",
		true,
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
	if err := issueCert(logger, cfg, algorithmEd25519, paths, hostname, nil, ""); err != nil {
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
		nil,
		"",
		true,
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

	if err := issueCert(logger, cfg, algorithmECDSA, paths, "host.example.test", nil, ""); err != nil {
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
		nil,
		"",
		true,
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
		nil,
		"",
		true,
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
	if err := issueCert(logger, cfg, algorithmECDSA, paths, hostname, nil, ""); err != nil {
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
		nil,
		"",
		true,
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
				tt.oldInternal,
				tt.oldExternal,
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
				tt.newInternal,
				tt.newExternal,
				true,
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

func TestCheckOneDefersIPSANComparisonWhenDiscoveryIsIncomplete(t *testing.T) {
	t.Parallel()

	cfg, paths, logger := newTestCertificateConfig(t, false, true)
	const hostname = "host.example.test"
	if err := issueCert(
		logger,
		cfg,
		algorithmECDSA,
		paths,
		hostname,
		nil,
		"198.51.100.10",
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
		nil,
		"",
		false,
	); err != nil {
		t.Fatalf("check certificate: %v", err)
	}

	after := loadTestCertificate(t, paths.cert)
	if before.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Fatal("certificate was reissued using incomplete IP discovery results")
	}
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

func newTestCertificateConfig(
	t *testing.T,
	internalIP bool,
	externalIP bool,
) (*config, certPaths, *slog.Logger) {
	t.Helper()

	baseDir := t.TempDir()
	cfg := &config{
		lifetime:   24 * time.Hour,
		certDir:    baseDir,
		notifyDir:  baseDir,
		internalIP: internalIP,
		externalIP: externalIP,
	}
	return cfg, certPathsForAlgorithm(cfg, algorithmECDSA), slog.New(slog.NewTextHandler(io.Discard, nil))
}

func loadTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	cert, err := loadCert(path)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	return cert
}
