# certd

`certd` is a self-signed TLS certificate generation and management daemon for Linux systems.
It runs as a systemd service, generates certificates on first start, and automatically re-issues them when the hostname
or IP addresses change, or when they are approaching expiry.
Dependent services are notified via filesystem notification files watched by systemd path units.

## Features

- Generates self-signed X.509 certificates using RSA 4096, ECDSA P-256, or Ed25519 keys
- Multiple algorithms can be active simultaneously, each producing independent certificate files
- Automatically detects hostname, internal IP addresses, and optionally the external (NAT) IP
- Re-issues certificates on hostname or IP address changes
- Re-issues certificates when `CERTD_LIFETIME` changes, so a new lifetime applies at the next poll
- Renews certificates when less than one third of their lifetime remains
- Notifies dependent services via per-algorithm notification files
- Exposes an HTTP health and Prometheus metrics endpoint
- Ships as a single static binary with no external dependencies

## Installation

```sh
sudo certd -install
```

This copies the binary to `/usr/local/bin/certd` and installs the systemd unit and sysusers configuration.
Then create the system user and enable the service:

```sh
sudo systemd-sysusers
sudo systemctl daemon-reload
sudo systemctl enable --now certd
```

> [!NOTE]
> `certd` creates and uses user and group named `certd`.
> Make sure there is no conflict with other programs.
> If needed, create different user and group then adjust settings in systemd unit.
> Remember to also reload systemd after making these changes.

## Configuration

All configuration is done via environment variables. The systemd unit sets sensible defaults for all options
— override them using a drop-in snippet rather than editing the unit file directly.

### Creating a drop-in override

```sh
sudo systemctl edit certd
```

This opens an editor for `/etc/systemd/system/certd.service.d/override.conf`. Add only the variables you want to change:

```ini
[Service]
Environment=CERTD_ED25519=true
Environment=CERTD_LIFETIME=10y
Environment=CERTD_EXTERNAL_IP=false
```

### Configuration reference

| Environment variable   | CLI flag          | Default               | Description                                                                                                      |
|------------------------|-------------------|-----------------------|------------------------------------------------------------------------------------------------------------------|
| `CERTD_ECDSA`          | `-ecdsa`          | `false`               | Generate and manage an ECDSA P-256 certificate                                                                   |
| `CERTD_ED25519`        | `-ed25519`        | `false`               | Generate and manage an Ed25519 certificate                                                                       |
| `CERTD_RSA`            | `-rsa`            | `false`               | Generate and manage an RSA 4096 certificate                                                                      |
| `CERTD_LIFETIME`       | `-lifetime`       | `1y`                  | Certificate lifetime. Accepts `y`, `w`, `d`, `h`, `m`, `s` and combinations such as `1y30d` or `90d12h`          |
| `CERTD_CERT_DIR`       | `-cert-dir`       | `/var/lib/certd`      | Directory where certificate and key files are written                                                            |
| `CERTD_NOTIFY_DIR`     | `-notify-dir`     | `/run/certd`          | Directory where notification files are written after a certificate is issued or renewed                          |
| `CERTD_INTERNAL_IP`    | `-internal-ip`    | `false`               | Include non-loopback IPv4 addresses of local interfaces in certificate SANs                                      |
| `CERTD_EXTERNAL_IP`    | `-external-ip`    | `false`               | Detect and include the external (NAT) IPv4 address in certificate SANs                                           |
| `CERTD_POLL_INTERVAL`  | `-poll-interval`  | `1h`                  | How often to check for hostname/IP changes and certificate expiry                                                |
| `CERTD_MAX_RETRIES`    | `-max-retries`    | `5`                   | Maximum number of retries for external IP detection, with exponential backoff                                    |
| `CERTD_HTTP_ADDR`      | `-http-addr`      | `127.0.0.1:8484`      | Address for the HTTP health and metrics server. Set to empty string to disable                                   |
| `GOMAXPROCS`           | —                 | —                     | Number of OS threads used by the Go runtime. `certd` is I/O-bound and does not benefit from more than one thread |

All three algorithm switches default to `false`. If none of them is enabled, `certd` falls back to a single
ECDSA certificate — so enabling only `CERTD_RSA` yields RSA alone, not RSA alongside ECDSA.

The table lists the defaults built into `certd`. The packaged systemd unit sets most of these explicitly, so a
default installation runs with the unit's values rather than these; see [files/etc/systemd/system/certd.service](files/etc/systemd/system/certd.service).
`GOMAXPROCS` has no `certd` default at all — the Go runtime uses the CPU count unless the unit pins it to `1`.

`CERTD_LIFETIME` must be at least `1h` and `CERTD_POLL_INTERVAL` at least `1m`. Re-issuing restarts every
dependent service, so rotating faster than that costs more than the shorter lifetime is worth.

The two must also agree with each other. Renewal begins once less than one third of the lifetime remains, and
`certd` only notices at a poll, so a poll has to fall inside that window: `CERTD_POLL_INTERVAL` must be shorter
than a third of `CERTD_LIFETIME`. A one-hour lifetime polled once an hour would expire before it was renewed, so
`certd` refuses to start on such a pairing rather than letting the certificate lapse. With the default one-hour
poll the shortest usable lifetime is just over three hours; the packaged unit polls every five minutes.

### CLI flags

CLI flags mirror environment variables and take precedence over them. Run `certd -help` for the full list.

Additional flags not available as environment variables:

| Flag        | Description                                                            |
|-------------|------------------------------------------------------------------------|
| `-install`  | Install the binary and embedded system files, then exit. Requires root |
| `-version`  | Print version, commit, and build date, then exit                       |

## Certificate files

For each enabled algorithm, `certd` writes two files to `CERTD_CERT_DIR`:

| Algorithm | Certificate          | Key                  |
|-----------|----------------------|----------------------|
| ECDSA     | `server_ecdsa.crt`   | `server_ecdsa.key`   |
| Ed25519   | `server_ed25519.crt` | `server_ed25519.key` |
| RSA       | `server_rsa.crt`     | `server_rsa.key`     |

Files are written with mode `0640`, owned by `certd:certd`. Services that need to read them should have their user added
to the `certd` group:

```sh
sudo usermod -aG certd myservice
```

## Certificate SANs

Every certificate always includes the following Subject Alternative Names:

- The system hostname (`hostname`)
- `localhost`
- `127.0.0.1`

When `CERTD_INTERNAL_IP=true`, all non-loopback IPv4 addresses of active network interfaces are also added.

When `CERTD_EXTERNAL_IP=true`, `certd` queries several external IP providers in order and adds the first valid IPv4 response:

1. `https://ipv4.icanhazip.com`
2. `https://checkip.amazonaws.com`
3. `https://ifconfig.io/ip`

If all providers fail, `certd` falls back to the last known external IP and logs a warning.
The certificate is only re-issued if the IP actually changes.

The two address sources are tracked separately, so a failure in one does not discard what the other established.
Discovery is incomplete when interface enumeration fails, or when no external IP is available and none is known.
The certificate is then compared against the SANs it would be issued with now, rather than against the raw
discovery results. Addresses this cycle could not confirm are carried over, so none is silently dropped,
while an address a working source contradicts is still removed.
An address that enumeration no longer reports is therefore dropped even while external detection is failing,
and an interface change is still acted on by a host with no internet access at all.
The set is reconciled on the next poll with complete discovery.

## Integrating dependent services

`certd` uses a notification file mechanism to signal dependent services when a certificate has been issued or renewed.
This keeps `certd` decoupled from the services that consume its certificates — it only writes a file,
and systemd handles the rest.

### Notification files

After issuing or renewing a certificate, `certd` touches a file in `CERTD_NOTIFY_DIR`:

| Algorithm | Notification file                 |
|-----------|-----------------------------------|
| ECDSA     | `/run/certd/cert-updated-ecdsa`   |
| Ed25519   | `/run/certd/cert-updated-ed25519` |
| RSA       | `/run/certd/cert-updated-rsa`     |

These files live in `/run/certd` which is a tmpfs directory recreated on every boot by systemd
via `RuntimeDirectory=certd`. On first boot the files do not exist;
`certd` creates them after issuing the initial certificate.

### Setting up a dependent service

`certd -install` creates additional systemd `.path` units that watches the relevant notification file
and a companion `.service` units that restarts the dependent service.
Both are template units using `%i` as the instance name.

There is a separate pair of `.path` and `.service` for each algorithm:

- `certd-notify-ecdsa@.path` and `certd-notify-ecdsa@.service` for **ECDSA**
- `certd-notify-ed25519@.path` and `certd-notify-ed25519@.service` for **Ed25519**
- `certd-notify-rsa@.path` and `certd-notify-rsa@.service` for **RSA**

Enable the path unit for each service that uses a certificate, substituting the service name as the instance:

```sh
# For a service configd using the ECDSA certificate
sudo systemctl enable --now certd-notify-ecdsa@configd.path

# Another example - nginx service using RSA certificate
sudo systemctl enable --now certd-notify-rsa@nginx.path
```

To list defined watchers, use:

```sh
systemctl list-units --type=path "certd-notify-*"

  UNIT                            LOAD   ACTIVE SUB     DESCRIPTION
  certd-notify-ecdsa@configd.path loaded active waiting Watch for certd ecdsa certificate update (configd)

Legend: LOAD   → Reflects whether the unit definition was properly loaded.
        ACTIVE → The high-level unit activation state, i.e. generalization of SUB.
        SUB    → The low-level unit activation state, values depend on unit type.

1 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
```

### Ordering: ensuring the certificate exists before the dependent service starts

Add the following to the dependent service's unit to prevent it from starting before `certd` has issued the certificate:

```ini
[Unit]
After=certd.service
Requires=certd.service
```

The `certd` unit reports systemd readiness only after its initial certificate cycle completes successfully.
This ensures that on first boot `certd` issues the certificate before the dependent service attempts to start.

## HTTP endpoints

When `CERTD_HTTP_ADDR` is set (default: `127.0.0.1:8484`), `certd` exposes two HTTP endpoints.
The server listens on localhost only by default and is not TLS-encrypted — it is intended for local consumption
by monitoring agents or the host's own web UI backend.

### `GET /health`

Returns a JSON document describing the status of all managed certificates.

**Response — all certificates healthy (`HTTP 200`):**

```json
{
  "status": "ok",
  "certs": {
    "ecdsa": {
      "status": "ok",
      "subject": "myhost.example.com",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2025-01-01T00:00:00Z",
      "remaining": "287h0m0s",
      "san_dns": ["myhost.example.com", "localhost"],
      "san_ip": ["127.0.0.1", "10.0.0.5"]
    }
  }
}
```

**Response — one or more certificates have an error (`HTTP 503`):**

```json
{
  "status": "error",
  "certs": {
    "ecdsa": {
      "status": "error",
      "error": "certificate not yet issued"
    }
  }
}
```

### `GET /metrics`

Returns Prometheus-format metrics.

| Metric                                           | Type    | Description                                               |
|--------------------------------------------------|---------|-----------------------------------------------------------|
| `certd_up`                                       | gauge   | Always `1` while `certd` is running                       |
| `certd_start_time_seconds`                       | gauge   | Unix timestamp when `certd` started                       |
| `certd_cert_not_before_seconds{algorithm="..."}` | gauge   | Certificate validity start as Unix timestamp              |
| `certd_cert_not_after_seconds{algorithm="..."}`  | gauge   | Certificate expiry as Unix timestamp                      |
| `certd_cert_renewals_total{algorithm="..."}`     | counter | Total number of times a certificate was issued or renewed |
| `certd_cert_errors_total{algorithm="..."}`       | counter | Total number of failed certificate issue attempts         |

Example Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: certd
    static_configs:
      - targets: ['127.0.0.1:8484']
```

A useful alerting rule for expiring certificates:

```yaml
- alert: CertdCertificateExpiringSoon
  expr: (certd_cert_not_after_seconds - time()) / 86400 < 30
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "certd certificate expiring in less than 30 days"
    description: "Algorithm {{ $labels.algorithm }} expires in {{ $value | humanizeDuration }}"
```

## Security

`certd` runs as a dedicated unprivileged system user `certd` with no login shell and no home directory.
The systemd unit applies the following hardening:

- `NoNewPrivileges=yes` — the process cannot gain additional privileges
- `CapabilityBoundingSet=` — all Linux capabilities are dropped
- `ProtectSystem=strict` — the filesystem is mounted read-only except for the certificate and notification directories
- `PrivateDevices=yes` — no access to physical devices
- `MemoryDenyWriteExecute=yes` — writable and executable memory mappings are blocked
- `SystemCallFilter=@system-service` — only a minimal set of syscalls is permitted
- `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `LockPersonality=yes` — additional kernel isolation

## Author

Krzysztof Ciepłucha

## Disclaimer

This tool was designed and built with the assistance of AI tools. The design
decisions, architecture, and all code have been reviewed and verified by a
human. The project goes through automated security checks, vulnerability
scanning, and static code analysis on every commit.

That said, this software is provided as-is with no guarantees. It may contain
bugs. **Use at your own risk.**

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
