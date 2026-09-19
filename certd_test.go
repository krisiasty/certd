// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Krzysztof Ciepłucha

package main

import (
	"crypto/x509"
	"io"
	"log/slog"
	"testing"
	"time"
)

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
