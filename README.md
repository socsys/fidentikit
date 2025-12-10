<p align="center">
  <img src="f-kit.png" alt="Fidentikit" width="400">
</p>

# FidentiKit - A Browser-Based Crawler for Large-Scale Passkey Adoption Measurements

## Architecture

### Core Components

- **brain**: Orchestration service (Flask API + UI)
- **landscape-worker**: Detects authentication mechanisms (passkeys, MFA, password) and IdPs
- **passkey-worker**: Deep analysis of passkey implementations with virtual authenticator
- **common**: Shared modules for browser automation, detection logic, and helpers

### Infrastructure

- **RabbitMQ**: Message broker for task distribution
- **MongoDB**: Data storage
- **MinIO**: Object storage for artifacts (screenshots, HAR files)
- **Redis**: Caching layer
- **Prometheus + Grafana**: Monitoring and metrics
- **Traefik**: Reverse proxy and load balancer

## Authentication Mechanisms

### Primary: Passkey
- UI detection (buttons, forms, attributes)
- JavaScript detection (WebAuthn API usage)
- Virtual authenticator for parameter capture
- Implementation analysis (create/get options, credentials, CDP events)

### Additional: MFA
- TOTP/Authenticator apps
- SMS verification
- Email verification
- QR codes

### Additional: Password
- Username/email + password forms
- Submit button detection

## Identity Providers

SSO detection for third-party providers:
- Apple
- Google
- Microsoft
- GitHub
- Facebook
- Twitter
- LinkedIn

## Usage

### Quickstart
1) Prereqs: Docker + Docker Compose; keep the ports below free.  
2) Clone: `git clone <repo-url> && cd Fidentikit`  
3) Configure: copy `.env.example` to `.env` (or set env vars inline) and adjust credentials/domains if needed.  
4) Start: `docker-compose build && docker-compose up -d` (or use the Prometheus variant if required).  
5) Verify: `docker ps` should show brain, workers, rabbitmq, mongodb, minio, redis, traefik, grafana, prometheus.  
6) Access UI: `http://localhost:8080/admin` (scan workflow below).

### Hostnames & Ports to keep free
- 80, 443: Traefik entrypoints for `*.docker.localhost` (Brain UI, dashboards).  
- 8080: Admin dashboard (scan launcher).  
- 8081: Database admin UI / results browser.  
- 9000: MinIO UI (if exposed).  
- 27017/27018: MongoDB (local binding).  
- 5672/15672: RabbitMQ (internal/API).  
- 6379: Redis.  
- 9090/3000: Prometheus/Grafana.  
If you change host bindings in `docker-compose.yml`, adjust accordingly. Ensure `/etc/hosts` has `127.0.0.1` entries for `brain.docker.localhost`, `grafana.docker.localhost`, `prometheus.docker.localhost`, `rabbitmq.docker.localhost`, `mongoexpress.docker.localhost`, `minio.docker.localhost`, `jupyter.docker.localhost` (or use the `localhost` ports above).

### Running a landscape scan (UI)
1) Go to the admin dashboard: `http://localhost:8080/admin`.  
2) Under **Run New Analyses**, click **Landscape**, then expand the dropdowns in the modal.  
3) Enter the domain you want to scan under **Domain**.  
4) You can tweak 40+ scan configurations; defaults are fine for initial tests.  
5) Click **Run Analysis**. One of the workers picks it up, runs the analysis, and pushes results to the web UI.  
6) After some time, visit `http://localhost:8081/db/sso-monitor/landscape_analysis_tres` to see the created database entry and analysis result.  
7) If results don’t appear, check worker logs: `docker compose logs -f landscape-worker passkey-worker`.

### Access Services
- Brain UI: http://brain.docker.localhost
- Grafana: http://grafana.docker.localhost
- Prometheus: http://prometheus.docker.localhost
- RabbitMQ: http://rabbitmq.docker.localhost

### Configuration
All services configured via environment variables in `.env` file or docker-compose.yml.

## Project Structure

```
Fidentikit/
├── common/                    # Shared modules
│   ├── modules/
│   │   ├── auth_mechanisms/  # Passkey, MFA, Password detection
│   │   ├── idps/             # SSO provider detection
│   │   ├── browser/          # Playwright automation
│   │   ├── helper/           # Utilities
│   │   ├── loginpagedetection/ # Login page discovery
│   │   └── locators/         # Element locators
│   └── lib/                  # External libraries
├── landscape-worker/         # Authentication landscape analysis
├── passkey-worker/          # Passkey implementation analysis
├── brain/                   # Orchestration service
├── prometheus/              # Metrics configuration
└── docker-compose.yml       # Service definitions
```

## Monitoring

Prometheus scrapes metrics from:
- Traefik (proxy metrics)
- RabbitMQ (queue metrics)
- MinIO (storage metrics)
- MongoDB (database metrics)
- Redis (cache metrics)
- Brain (application metrics)

Grafana dashboards visualize all metrics with customizable views.


