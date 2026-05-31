# HORUS IDS

Hierarchical Network Intrusion Detection System built for a campus SOC environment.

Uses a 2-level XGBoost classifier trained on CIC-IDS2017, CIC-IDS2018, and CIC-DDoS2019 to detect 11 attack classes in real-time network traffic.

## Performance

| Metric | Score |
|---|---|
| F1 (weighted) | 98.70% |
| Accuracy | 98.72% |
| False Alarm Rate | 0.178% |
| Inference | ~16ms per flow |

Evaluated on 1.6M unseen flows (data never seen during training).

## Attack Classes

| Level 1 Group | Fine Classes | Severity |
|---|---|---|
| BENIGN | BENIGN | info |
| DDoS-family | DDoS, DDoS Amplification, DDoS Volumetric | critical |
| DoS-family | DoS Hulk, DoS GoldenEye, DoS Slow | critical |
| Brute-force | FTP-Patator, SSH-Patator | medium |
| PortScan | PortScan | medium |
| Bot | Bot | high |

## Project Structure

```
api/                     FastAPI REST API + WebSocket
api/routes/              Endpoint routers (predict, auth, alerts, analytics, ai)
application/services/    Use cases (prediction, auth, alerts, history, AI chat)
domain/                  Entities, ports (interfaces), exceptions, value objects
infrastructure/
  ml/                    XGBoost model gateway + feature engineering
  persistence/           SQLite repositories (predictions, users, alerts)
  external/              Groq LLM client
  websocket/             Real-time prediction broadcast
capture/                 Network traffic capture pipeline
  sources/               nfstream, NetFlow v5/v9/IPFIX, Syslog, SNMP trap
  alert_router.py        Per-VLAN severity escalation + RFC 5424 syslog
  response.py            Automated switch response via SSH
data_utils/              Constants, feature engineering, CSV loading
training/                Model training + evaluation scripts
nexus-frontend/          React dashboard
  src/pages/             Dashboard, LiveLogs, Upload, Alerts, History, Statistics
  src/components/        AiChatbot, Badge, ConfidenceBar, ErrorBoundary
  src/context/           AuthContext (session management)
nginx/                   Reverse proxy config (TLS termination + WebSocket)
systemd/                 Service files for API + capture
tests/                   25 test modules + fixtures
tools/                   SSH enable, SNMP config, NetFlow test sender
plots/                   Confusion matrices + metric comparison charts
```

## Input Paths

- **RSPAN** (eth1) -> nfstream -> flow features -> `/predict/batch`
- **NetFlow v5/v9/IPFIX** (UDP 2055) -> parser -> flow features -> `/predict/batch`
- **Syslog** (UDP 514) -> Cisco IOS event correlation
- **SNMP Traps** (UDP 162) -> switch event logging

## Automated Response

Predictions trigger per-VLAN severity escalation and automated switch response via SSH:

- **DDoS** -> ACL block / Palo Alto edge tag
- **DoS** -> ACL block on distribution SVI
- **Brute-force** -> ACL block + port shutdown
- **PortScan / Bot** -> isolate to VLAN 999

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/AbanoubYossef/Horus-IDS.git
cd Horus-IDS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Install frontend dependencies
cd nexus-frontend && npm install && cd ..

# 3. Place trained models in models/hierarchical_11class/

# 4. Run
cp .env.example .env
make dev             # API on localhost:8000
make dev-frontend    # Frontend on localhost:3000
```

### Docker

```bash
cp .env.example .env
# Place models in ./models/
docker compose up -d horus-api          # API only
docker compose --profile tls up -d      # API + nginx TLS
docker compose --profile capture up -d  # API + capture service
```

## Frontend

React SPA served by Vite in development, built into static files for Docker.

**Pages:** Landing, Dashboard, Live Logs, Upload CSV, Alerts, History, Statistics, Threat Map

**Features:**
- Real-time flow monitoring via WebSocket
- CSV upload with per-row predictions and ground-truth accuracy
- Alert management (create, investigate, resolve)
- AI chatbot (Groq LLM) for attack analysis
- Light/dark theme toggle
- VLAN-aware flow labeling (building + segment names)

## Testing

```bash
make test       # full suite, no model needed
make test-cov   # with coverage report
```

## Stack

- **ML**: XGBoost + Optuna + 20 engineered features
- **API**: FastAPI + SQLite + Pydantic
- **Frontend**: React + Vite + Recharts
- **Capture**: nfstream + NetFlow parser + BER SNMP decoder
- **Deploy**: Docker Compose + nginx TLS + systemd

## Author

Abanoub Youssef - UTCN, Automatica si Calculatoare
