# Environment Analyzer

A Node.js web application that analyzes the runtime environment of a workspace. It inspects installed packages, checks for available security updates against Ubuntu repositories, and provides visibility into process isolation, filesystem access, resource limits, and more.

## Features

- **Package Analysis** — Reads installed packages via `dpkg -l` and compares versions against `noble-security` and `noble-updates` Ubuntu repositories
- **Process Visibility** — Lists all visible processes via `ps aux`
- **Environment Variables** — Shows readable `/proc/{pid}/environ` entries (key names only, never values)
- **Filesystem Exposure** — Checks access to sensitive paths (`.ssh`, `.env`, `/etc/shadow`, etc.)
- **Resource Info** — Reports RAM, CPU, and cgroup enforcement status
- **System Info** — OS, kernel, architecture, uptime, dpkg package count
- **Network** — Lists all listening ports
- **User Context** — UID, GID, groups
- **Env Vars** — All environment variable key names of the running process
- **Kubernetes Probe** — Checks for K8s service account, namespace, and API access
- **DNS** — Nameserver config from `/etc/resolv.conf` and DNS resolution probes (K8s, workspace, external)
- **Linux Capabilities** — Decoded CapEff/CapPrm/CapBnd from `/proc/1/status`
- **Security Modules** — AppArmor profile, Seccomp mode, active LSMs
- **System Users** — Parsed `/etc/passwd` with human/system user classification
- **Mounts** — All mounts from `/proc/mounts` (CephFS, tmpfs, overlay, etc.)
- **Outbound Access** — TCP connect probes to external targets (DNS, HTTPS, npm, Nix cache) and external IP detection
- **Nix** — Nix version, channels, installed packages, store size and path count

## Quick Start

### Local (Docker)

```bash
docker compose up --build
```

Open http://localhost:3000

### Codesphere

Push to a Codesphere workspace. The `ci.yml` handles install and startup automatically.

## Tech Stack

- **Backend:** Node.js, Express, better-sqlite3
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Data:** SQLite (in-memory cache for package scan results)

## Project Structure

```
server.js              # Express server + API routes
lib/
  parser.js            # dpkg -l and Packages.gz parsers
  db.js                # SQLite database layer
  repo.js              # Ubuntu repository fetcher
  security.js          # System inspection (processes, env, fs, resources, etc.)
public/
  index.html           # Dashboard with tab navigation
  style.css            # Dark theme UI
  app.js               # Tab switching logic
  tabs/
    packages.js        # Package tab rendering
    security.js        # Security tabs rendering
ci.yml                 # Codesphere CI/CD config
Dockerfile             # Ubuntu 24.04 + Node.js 22
docker-compose.yml     # Local development
```

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/packages` | List packages (supports `search`, `filter`, `sortBy`, `sortDir`) |
| `GET /api/stats` | Package scan statistics |
| `POST /api/refresh` | Re-scan packages against Ubuntu repos |
| `GET /api/security/overview` | All security data in one request |
| `GET /api/security/processes` | Process list |
| `GET /api/security/env-leakage` | /proc environ readability per PID |
| `GET /api/security/env-keys` | Own process env var key names |
| `GET /api/security/filesystem` | Sensitive path access checks |
| `GET /api/security/resources` | RAM, CPU, cgroups |
| `GET /api/security/system` | OS and system info |
| `GET /api/security/network` | Listening ports |
| `GET /api/security/user` | User context (UID, GID, groups) |
| `GET /api/security/kubernetes` | K8s API probe |
| `GET /api/security/dns` | DNS config and resolution probes |
| `GET /api/security/capabilities` | Linux capabilities (CapEff/CapPrm/CapBnd) |
| `GET /api/security/securitymodules` | AppArmor, Seccomp, LSM status |
| `GET /api/security/systemusers` | /etc/passwd user list |
| `GET /api/security/mounts` | /proc/mounts filesystem mounts |
| `GET /api/security/outbound` | Outbound connectivity probes |
| `GET /api/security/nix` | Nix version, channels, store info |

## License

MIT
