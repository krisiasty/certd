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

### Requirements

The packaged unit is written for **systemd 247 or newer**. It loads on older releases, but systemd logs
directives it does not recognise as `Unknown lvalue` and ignores them, so an older release silently applies
less hardening than the unit appears to describe:

| Directive                               | Added in systemd |
|-----------------------------------------|------------------|
| `ProcSubset=`, `ProtectProc=`           | 247              |
| `ProtectClock=`                         | 245              |
| `ProtectKernelLogs=`                    | 244              |
| `ProtectHostname=`, `RestrictSUIDSGID=` | 242              |
| `StateDirectory=`, `LockPersonality=`   | 235              |

Below 235 the unit does not work at all: `StateDirectory=` is ignored, `/var/lib/certd` is never created, and
`certd` cannot write its certificates. That rules out RHEL 7 and SLES 12. Between 235 and 246 the unit runs,
but the `/proc` restrictions are not in force.

### Installing

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
| `CERTD_INTERFACES`     | `-interfaces`     | `default-route`       | Interfaces to take internal IPs from: `default-route`, `all`, or a list of interface names                       |
| `CERTD_EXTERNAL_IP`    | `-external-ip`    | `false`               | Detect and include the external (NAT) IPv4 address in certificate SANs                                           |
| `CERTD_EXTRA_SANS`     | `-extra-sans`     | —                     | Extra subject alternative names, comma separated: IP addresses or DNS names, always certified                    |
| `CERTD_POLL_INTERVAL`  | `-poll-interval`  | `1h`                  | How often to check for hostname/IP changes and certificate expiry                                                |
| `CERTD_MAX_RETRIES`    | `-max-retries`    | `5`                   | Maximum number of retries for external IP detection, with exponential backoff                                    |
| `CERTD_HTTP_ADDR`      | `-http-addr`      | `127.0.0.1:8484`      | Address for the HTTP health and metrics server. Set to empty string to disable                                   |
| `GOMAXPROCS`           | —                 | —                     | Number of OS threads used by the Go runtime. `certd` is I/O-bound and does not benefit from more than one thread |

All three algorithm switches default to `false`. If none of them is enabled, `certd` falls back to a single
ECDSA certificate — so enabling only `CERTD_RSA` yields RSA alone, not RSA alongside ECDSA.

The table lists the defaults built into `certd`. The packaged systemd unit sets most of these explicitly, so a
default installation runs with the unit's values rather than these; see [files/etc/systemd/system/certd.service](files/etc/systemd/system/certd.service).
`GOMAXPROCS` has no `certd` default at all — the Go runtime uses the CPU count unless the unit pins it to `1`.

All settings are read once at startup. A value that cannot be understood is rejected and `certd` refuses to
start, reporting every unusable variable at once so the configuration can be fixed in one pass rather than one
restart per mistake.

Booleans accept `true` or `false`, in any case, and nothing else. `yes`, `on` and `1` are errors rather than
being read as `false`. Numbers must be whole and complete, so `3.9` and `5x` are rejected rather than read as
`3` and `5`.

Each setting is bounded at both ends, and a value outside its range is rejected at startup:

| Setting               | Range         |
|-----------------------|---------------|
| `CERTD_LIFETIME`      | `1h` to `25y` |
| `CERTD_POLL_INTERVAL` | `1m` to `1d`  |
| `CERTD_MAX_RETRIES`   | `1` to `20`   |

Re-issuing restarts every dependent service, so rotating faster than an hour costs more than the shorter
lifetime is worth. At the other end `certd` issues self-signed certificates with no revocation path, so the
lifetime is the whole window in which a leaked key stays usable; 25 years already outlives the host it
identifies. A poll interval longer than a day would leave a hostname or address change unnoticed for that long,
which is the very thing `certd` runs to catch.

`CERTD_MAX_RETRIES` is bounded because every retry delays the poll it belongs to. The delay between external IP
attempts doubles from one second and then holds at sixteen, and nothing is waited after the final attempt, so
the default of five retries waits 15 seconds in total and the maximum of twenty waits 4 minutes 15 seconds.
Without that ceiling each retry would cost as much as all the ones before it together, and twenty retries would
wait twelve days — holding back the systemd readiness notification just as long, since it is only sent once the
first check completes.

Retries are also held against the poll interval: `certd` refuses to start when they would wait longer than a
single poll, because the next poll would have made the same attempt sooner. That only binds on short intervals.
A one-minute poll affords seven retries; five minutes or more affords the full twenty. Both retry checks are
skipped when `CERTD_EXTERNAL_IP` is off, since nothing is retried then.

The budget counts only the waiting. A provider that refuses a connection fails immediately, while one that drops
the packets costs up to a further five seconds each, which is why a failing check can take longer than the
figures above.

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

When `CERTD_INTERNAL_IP=true`, the host's own IPv4 addresses are added. By default they are taken from the
interface carrying the default route, which keeps container and virtual bridges such as `docker0`, `br-*` and
`virbr0` out of the certificate. Those appear and disappear as containers and networks are created and removed,
and every change would re-issue the certificate and restart each dependent service.

`CERTD_INTERFACES` selects where the addresses come from, and defaults to `default-route`:

| Value           | Meaning                                                                          |
|-----------------|----------------------------------------------------------------------------------|
| `default-route` | The interface carrying the default route. This is also what an empty value means |
| `all`           | Every non-loopback interface                                                     |
| `eth0,eth1`     | Exactly the interfaces named                                                     |

A host that serves on more than one network needs `all` or an explicit list, or the addresses on its other
networks are left out of the certificate.

A host with no default route at all — air-gapped, on an isolated segment, or with a lapsed DHCP lease — falls
back to every non-loopback interface and logs a warning.

Link-local addresses (`169.254.0.0/16`) are never included. A host assigns itself one when DHCP fails, so
including it would re-issue the certificate when the lease is lost and again when it returns, each time to name
an address nothing can reach the host on.

When `CERTD_EXTERNAL_IP=true`, `certd` queries several external IP providers in order and adds the first valid IPv4 response:

1. `https://ipv4.icanhazip.com`
2. `https://checkip.amazonaws.com`
3. `https://ifconfig.io/ip`

A provider counts as having answered only when it returns `200` with a body that parses as an IPv4 address.
Anything else — a connection failure, a `429` or `503`, or a body that is not an address — is logged and the
next provider is tried. The body of an unsuccessful response is never read as an answer: a proxy or captive
portal replying with something address-shaped is describing itself rather than this host.

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

### Additional names and addresses

`CERTD_EXTRA_SANS` adds subject alternative names that are always certified, whether or not this host holds
them. Entries that parse as IP addresses become IP SANs and the rest become DNS SANs; anything that is neither
is rejected at startup, so a mistyped address is not quietly certified as a host name.

```sh
CERTD_EXTRA_SANS=10.0.0.100,vip.example.com,*.apps.example.com
```

This is how to certify a floating address. A VRRP or Pacemaker VIP exists only on the node currently holding it,
so detection would place it in that node's certificate alone — and at failover the node taking over would serve
a certificate that is not valid for the address clients are connecting to, until its next poll re-issued the
certificate and restarted the service. Configuring the address instead puts it in every node's certificate
permanently, so a failover changes nothing and triggers no re-issue on either node.

It is also the only way to certify an address the host cannot see at all. An AWS Elastic IP or an OpenStack
floating IP is translated by the network and never appears on an interface, so no amount of detection will find
it.

### Fully qualified domain names

The certificate carries the hostname the kernel reports, which on many Linux systems is a short name such as
`web01` rather than `web01.example.com`. **If clients connect by a fully qualified name, configure it
explicitly:**

```sh
CERTD_EXTRA_SANS=web01.example.com
```

A host whose kernel hostname is already fully qualified needs nothing — that name is certified as it stands.

`certd` does not try to work the FQDN out for itself. On Linux the kernel stores only the hostname, and the
fully qualified form is a matter of convention: it may come from an `/etc/hosts` entry, from a DNS search
domain, from a reverse lookup, or from nowhere at all. Every way of deriving it depends on configuration that
can be absent, disagree with the others, or change while `certd` is running. A name derived that way would also
change the certificate's SANs when it changed, re-issuing the certificate and restarting every dependent
service — and unlike a stale IP SAN, a wrong name is the one clients check, so getting it wrong breaks TLS
rather than merely adding something unused.

Names and addresses are deduplicated and sorted, so two certificates issued from the same configuration list
their SANs identically. Combined with `CERTD_INTERNAL_IP=false` and `CERTD_EXTERNAL_IP=false`, this gives
certificates whose contents are entirely determined by configuration, with no detection at all.

## Integrating dependent services

`certd` uses a notification file mechanism to signal dependent services when a certificate has been issued or renewed.
This keeps `certd` decoupled from the services that consume its certificates — it only writes a file,
and systemd handles the rest.

Because touching that file restarts every service that depends on the certificate, `certd` stops issuing and
notifying as soon as it is asked to shut down, and leaves any remaining work to the next start. A `SIGTERM`
arriving mid-cycle therefore never restarts dependent services on the way out, and `certd` still exits zero.

Certificates and keys are replaced by writing a staging file alongside the target and renaming it into place, so
a reader never sees a partly written file. A process killed outright between the two steps leaves the staging
file behind, holding a private key; `certd` removes any it finds in `CERTD_CERT_DIR` at startup, for every
algorithm, including ones that are no longer enabled.

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

## Failure behaviour

A failure that a later poll could clear — an external IP provider that is down, interface enumeration that
fails, a certificate that could not be written — is logged, counted in `certd_cert_errors_total`, and retried
on the next poll. `certd` stays running and keeps serving the certificates already on disk.

A failure that cannot clear ends the process instead, so that systemd sees it: invalid configuration, an HTTP
address already in use, or a hostname that cannot be read. The unit restarts `certd` every ten seconds and
gives up after five attempts, leaving the unit in the `failed` state:

```ini
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5
```

The start limit matters. Without it, `RestartSec=10` spaces restarts far enough apart that systemd's default
limit of five starts within ten seconds can never be reached, and a permanently broken `certd` restarts
indefinitely without ever reaching `failed` — so `systemctl is-failed` and anything built on it stay quiet.
After it gives up, fix the cause and run `systemctl reset-failed certd` before starting it again.

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
