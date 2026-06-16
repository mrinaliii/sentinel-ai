# 🛡️ Sentinel-AI — AI-Powered SOC Analyst Assistant

<div align="center">

![Sentinel-AI Banner](docs/assets/banner.png)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://elastic.co)
[![LangChain](https://img.shields.io/badge/LangChain-0.2+-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white)](https://langchain.com)
[![Ollama](https://img.shields.io/badge/Ollama-Llama3-black?style=for-the-badge&logo=ollama&logoColor=white)](https://ollama.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

**An autonomous, LLM-powered Security Operations Center (SOC) analyst that triages alerts, correlates threats, maps to MITRE ATT&CK, and generates human-readable incident reports — entirely on-premises.**

[Features](#-key-features) · [Architecture](#-architecture-overview) · [Getting Started](#-getting-started) · [Roadmap](#-future-roadmap) · [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [System Objectives](#-system-objectives)
- [Key Features](#-key-features)
- [Architecture Overview](#-architecture-overview)
- [Folder Structure](#-folder-structure)
- [Technology Stack](#-technology-stack)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Future Roadmap](#-future-roadmap)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**Sentinel-AI** is an enterprise-grade, on-premises AI assistant designed to augment and accelerate Security Operations Center (SOC) workflows. It ingests raw security events from SIEM platforms, applies LLM-driven reasoning via **Llama 3** (served locally through **Ollama**), correlates findings against the **MITRE ATT&CK** framework, and surfaces actionable intelligence through a modern **React** dashboard.

Unlike cloud-dependent AI security tools, Sentinel-AI is architected for **air-gapped and privacy-first environments** — your logs, your data, your models, all on your infrastructure.

> **⚠️ Disclaimer:** Sentinel-AI is a decision-support tool. All AI-generated triage and recommendations must be reviewed by qualified security personnel before action is taken. This tool does not replace human judgment.

---

## 🎯 System Objectives

| # | Objective | Description |
|---|-----------|-------------|
| 1 | **Reduce Alert Fatigue** | Automatically triage and prioritize security alerts, filtering noise from true positives using contextual AI reasoning |
| 2 | **Accelerate Threat Investigation** | Provide SOC analysts with instant, context-rich summaries and hypotheses for each security event |
| 3 | **Standardize Threat Classification** | Map every detected behavior to MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs) automatically |
| 4 | **Enable Natural Language Querying** | Allow analysts to query the SIEM using plain English instead of complex DSL queries |
| 5 | **Automate Incident Reporting** | Generate structured, human-readable incident reports with remediation recommendations |
| 6 | **Preserve Data Sovereignty** | Operate entirely on-premises with local LLMs — no data leaves the organization's boundary |
| 7 | **Integrate Seamlessly** | Support OpenSearch-compatible SIEM ingestion for broad interoperability with existing tooling |

---

## ✨ Key Features

### 🤖 AI-Driven Alert Triage
- Automatic severity classification (Critical / High / Medium / Low / Informational)
- False-positive suppression using contextual enrichment and behavioral baselines
- Confidence scoring for every AI-generated assessment
- Analyst feedback loop for continuous model improvement

### 🗺️ MITRE ATT&CK Integration
- Real-time mapping of alerts to ATT&CK Tactics, Techniques, and Sub-techniques
- Automated ATT&CK Navigator layer generation for campaign visualization
- Technique prevalence scoring across the incident timeline
- Kill-chain stage identification for each threat

### 🔍 Natural Language SIEM Query Engine
- Plain-English query interface that translates to Elasticsearch/OpenSearch DSL
- Contextual query suggestions based on current active incidents
- Query history and saved searches per analyst session
- Explainable query breakdown showing what was searched and why

### 📊 Threat Correlation Engine
- Cross-alert correlation to identify multi-stage attack campaigns
- Entity-based graph linking (user → host → process → network)
- Temporal pattern analysis for time-series anomaly detection
- IOC enrichment from threat intelligence feeds

### 📝 Automated Incident Reporting
- One-click incident report generation in Markdown and PDF
- Executive summary and technical detail sections
- Recommended remediation steps grounded in ATT&CK mitigations
- Chain-of-custody timeline for forensic traceability

### 💬 Interactive Analyst Copilot
- Conversational interface for follow-up investigation questions
- Memory-augmented sessions preserving investigation context
- Hypothesis generation and evidence-gathering guidance
- Integration with runbooks and SOC playbooks

### 🔒 Privacy-First Architecture
- 100% local LLM inference via Ollama + Llama 3
- No external API calls for sensitive security data
- Role-based access control (RBAC) for analyst tiers
- Full audit logging of all AI interactions

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SENTINEL-AI PLATFORM                         │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────────────────────────┐   │
│  │   React Frontend  │    │           FastAPI Backend            │   │
│  │                  │    │                                      │   │
│  │  ┌────────────┐  │    │  ┌─────────────┐  ┌─────────────┐   │   │
│  │  │  Dashboard  │◄─┼────┼─►│  REST API   │  │  WebSocket  │   │   │
│  │  │  Alert Feed │  │    │  │  /api/v1/   │  │  /ws/       │   │   │
│  │  │  Chat UI    │  │    │  └──────┬──────┘  └──────┬──────┘   │   │
│  │  │  ATT&CK Map │  │    │         │                │          │   │
│  │  └────────────┘  │    │  ┌──────▼──────────────────▼──────┐  │   │
│  └──────────────────┘    │  │         Core Services           │  │   │
│                           │  │                                 │  │   │
│  ┌──────────────────┐    │  │  ┌──────────┐  ┌───────────┐   │  │   │
│  │   SIEM / Log     │    │  │  │  Triage  │  │  Report   │   │  │   │
│  │   Sources        │    │  │  │  Engine  │  │ Generator │   │  │   │
│  │                  │    │  │  └────┬─────┘  └─────┬─────┘   │  │   │
│  │  • Firewall      ├────┼──►       │               │         │  │   │
│  │  • IDS/IPS       │    │  │  ┌────▼───────────────▼──────┐  │  │   │
│  │  • EDR           │    │  │  │     LangChain Agent Layer  │  │  │   │
│  │  • Auth Logs     │    │  │  │                            │  │  │   │
│  │  • Cloud Events  │    │  │  │  ┌──────────┐ ┌────────┐  │  │  │   │
│  └──────────────────┘    │  │  │  │  Memory  │ │ Tools  │  │  │  │   │
│                           │  │  │  │  (Conv.) │ │(Search │  │  │  │   │
│  ┌──────────────────┐    │  │  │  └──────────┘ │ ,IOC,  │  │  │  │   │
│  │  Ollama Runtime  │    │  │  │               │ ATT&CK)│  │  │  │   │
│  │                  │◄───┼──┼──┼───────────────└────────┘  │  │  │   │
│  │  ┌────────────┐  │    │  │  └────────────────────────────┘  │  │   │
│  │  │  Llama 3   │  │    │  └─────────────────────────────────┘  │   │
│  │  │  (Local)   │  │    │                                      │   │
│  │  └────────────┘  │    │  ┌──────────────────────────────────┐  │   │
│  └──────────────────┘    │  │         Data Layer               │  │   │
│                           │  │                                  │  │   │
│  ┌──────────────────┐    │  │  ┌──────────────┐  ┌──────────┐  │  │   │
│  │  MITRE ATT&CK    │    │  │  │Elasticsearch │  │ Vector   │  │  │   │
│  │  Framework       │◄───┼──┼──┤ / OpenSearch │  │   DB     │  │  │   │
│  │                  │    │  │  │  (Events,    │  │(Embeddings│  │  │   │
│  │  • Tactics       │    │  │  │   Alerts,    │  │ for RAG) │  │  │   │
│  │  • Techniques    │    │  │  │   Incidents) │  └──────────┘  │  │   │
│  │  • Mitigations   │    │  │  └──────────────┘                │  │   │
│  └──────────────────┘    │  └──────────────────────────────────┘  │   │
│                           └──────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Raw Log Event
     │
     ▼
[Ingestion Layer] ──► Normalize & Parse ──► Enrich with Context
     │
     ▼
[Elasticsearch Index] ──► Alert Detection Rules ──► Alert Queue
     │
     ▼
[LangChain Agent] ──► Semantic Analysis ──► ATT&CK Mapping
     │
     ▼
[Llama 3 via Ollama] ──► Triage Assessment ──► Confidence Score
     │
     ▼
[Correlation Engine] ──► Campaign Linking ──► Incident Creation
     │
     ▼
[Report Generator] ──► Analyst Dashboard ──► SOC Ticket
```

### Component Interaction

| Component | Role | Communication |
|-----------|------|---------------|
| **React Frontend** | Analyst interface, dashboard, chat | REST + WebSocket |
| **FastAPI Backend** | Business logic, routing, auth | Synchronous + Async |
| **LangChain Agent** | LLM orchestration, tool usage, memory | Internal Python |
| **Ollama / Llama 3** | Local LLM inference | HTTP (localhost) |
| **Elasticsearch** | Event storage, full-text search, aggregations | Elasticsearch DSL |
| **OpenSearch Ingestor** | Log normalization and indexing | Logstash / Fluent Bit |
| **MITRE ATT&CK** | TTP reference and enrichment | Local JSON / TAXII |
| **Vector Store** | Semantic search, RAG embeddings | FAISS / ChromaDB |

---

## 📁 Folder Structure

```
sentinel-ai/
│
├── README.md                          # This file
├── .gitignore                         # Git exclusion rules
├── .env.example                       # Environment variable template
├── docker-compose.yml                 # Full-stack orchestration
│
├── backend/                           # FastAPI application
│   ├── main.py                        # Application entrypoint
│   ├── requirements.txt               # Python dependencies
│   ├── pyproject.toml                 # Project metadata & tool config
│   │
│   ├── api/                           # API route definitions
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── alerts.py              # Alert CRUD & triage endpoints
│   │   │   ├── incidents.py           # Incident management endpoints
│   │   │   ├── query.py               # NL-to-DSL query translation
│   │   │   ├── reports.py             # Incident report generation
│   │   │   ├── chat.py                # Copilot chat endpoints
│   │   │   └── mitre.py              # ATT&CK mapping endpoints
│   │   └── websocket.py              # Real-time WebSocket handlers
│   │
│   ├── core/                          # Core application configuration
│   │   ├── config.py                  # Settings (Pydantic BaseSettings)
│   │   ├── security.py                # Auth, JWT, RBAC
│   │   ├── logging.py                 # Structured logging setup
│   │   └── exceptions.py             # Custom exception handlers
│   │
│   ├── agents/                        # LangChain agent definitions
│   │   ├── __init__.py
│   │   ├── soc_agent.py              # Primary SOC analyst agent
│   │   ├── triage_agent.py           # Dedicated triage sub-agent
│   │   ├── correlation_agent.py      # Cross-alert correlation agent
│   │   └── report_agent.py           # Incident report writer agent
│   │
│   ├── tools/                         # LangChain custom tools
│   │   ├── __init__.py
│   │   ├── elasticsearch_tool.py     # ES search and aggregation tool
│   │   ├── mitre_lookup_tool.py      # ATT&CK framework lookup tool
│   │   ├── ioc_enrichment_tool.py    # IOC reputation lookup tool
│   │   ├── entity_graph_tool.py      # Entity correlation graph tool
│   │   └── playbook_tool.py          # SOC playbook retrieval tool
│   │
│   ├── chains/                        # LangChain chain definitions
│   │   ├── __init__.py
│   │   ├── triage_chain.py           # Alert triage reasoning chain
│   │   ├── nl_query_chain.py         # NL-to-DSL translation chain
│   │   └── report_chain.py           # Report generation chain
│   │
│   ├── memory/                        # Conversation & session memory
│   │   ├── __init__.py
│   │   ├── session_memory.py         # Per-session analyst memory
│   │   └── vector_memory.py          # Long-term vector store memory
│   │
│   ├── models/                        # Pydantic data models
│   │   ├── __init__.py
│   │   ├── alert.py                  # Alert schema
│   │   ├── incident.py               # Incident schema
│   │   ├── report.py                 # Report schema
│   │   ├── mitre.py                  # ATT&CK TTP schema
│   │   └── user.py                   # User & role schema
│   │
│   ├── services/                      # Business logic services
│   │   ├── __init__.py
│   │   ├── alert_service.py          # Alert ingestion & management
│   │   ├── triage_service.py         # Triage orchestration
│   │   ├── correlation_service.py    # Alert correlation logic
│   │   ├── mitre_service.py          # MITRE ATT&CK enrichment
│   │   ├── report_service.py         # Report compilation & export
│   │   └── ollama_service.py         # Ollama LLM client wrapper
│   │
│   ├── ingestion/                     # SIEM log ingestion pipeline
│   │   ├── __init__.py
│   │   ├── parser.py                 # Log format parsers (CEF, ECS, LEEF)
│   │   ├── normalizer.py             # Event field normalization
│   │   ├── opensearch_ingestor.py    # OpenSearch-compatible ingestor
│   │   └── pipelines/
│   │       ├── firewall.py           # Firewall log pipeline
│   │       ├── edr.py                # EDR event pipeline
│   │       └── auth.py               # Authentication log pipeline
│   │
│   ├── db/                            # Database layer
│   │   ├── __init__.py
│   │   ├── elasticsearch.py          # ES client & index management
│   │   └── vector_store.py           # FAISS/ChromaDB vector store
│   │
│   └── prompts/                       # LLM prompt templates
│       ├── triage_prompt.py          # Alert triage prompts
│       ├── correlation_prompt.py     # Threat correlation prompts
│       ├── report_prompt.py          # Incident report prompts
│       └── query_prompt.py           # NL query translation prompts
│
├── frontend/                          # React application
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   │
│   ├── public/
│   │   └── favicon.ico
│   │
│   └── src/
│       ├── main.tsx                   # React entrypoint
│       ├── App.tsx                    # Root application component
│       │
│       ├── components/                # Reusable UI components
│       │   ├── AlertFeed/            # Real-time alert list
│       │   ├── AlertCard/            # Individual alert card
│       │   ├── SeverityBadge/        # Severity indicator
│       │   ├── MitreMatrix/          # ATT&CK matrix heatmap
│       │   ├── ChatPanel/            # Copilot conversation UI
│       │   ├── IncidentTimeline/     # Forensic event timeline
│       │   ├── EntityGraph/          # D3.js entity relationship graph
│       │   └── ReportViewer/         # Incident report display
│       │
│       ├── pages/                     # Top-level route pages
│       │   ├── Dashboard.tsx         # Main SOC dashboard
│       │   ├── Alerts.tsx            # Alert management page
│       │   ├── Incidents.tsx         # Incident investigation page
│       │   ├── ThreatIntel.tsx       # Threat intelligence page
│       │   ├── Reports.tsx           # Generated reports page
│       │   ├── QueryLab.tsx          # NL query interface
│       │   └── Settings.tsx          # Configuration page
│       │
│       ├── hooks/                     # Custom React hooks
│       │   ├── useAlerts.ts          # Alert data fetching
│       │   ├── useWebSocket.ts       # Real-time event streaming
│       │   ├── useChat.ts            # Copilot chat state
│       │   └── useMitre.ts           # ATT&CK data hooks
│       │
│       ├── store/                     # State management (Zustand)
│       │   ├── alertStore.ts
│       │   ├── incidentStore.ts
│       │   └── chatStore.ts
│       │
│       ├── api/                       # API client layer
│       │   ├── client.ts             # Axios instance & interceptors
│       │   ├── alerts.ts
│       │   ├── incidents.ts
│       │   └── chat.ts
│       │
│       ├── types/                     # TypeScript type definitions
│       │   ├── alert.ts
│       │   ├── incident.ts
│       │   └── mitre.ts
│       │
│       └── styles/                    # Global CSS & design tokens
│           ├── globals.css
│           └── tokens.css
│
├── docker/                            # Docker configuration files
│   ├── Dockerfile.backend            # FastAPI container
│   ├── Dockerfile.frontend           # React container
│   ├── elasticsearch/
│   │   └── elasticsearch.yml         # ES cluster config
│   ├── logstash/
│   │   ├── logstash.conf             # Logstash pipeline config
│   │   └── patterns/                 # Grok pattern files
│   └── nginx/
│       └── nginx.conf                # Reverse proxy config
│
├── docs/                              # Project documentation
│   ├── architecture.md               # Detailed architecture doc
│   ├── api-reference.md              # API endpoint documentation
│   ├── deployment-guide.md           # Production deployment guide
│   ├── analyst-guide.md              # End-user analyst manual
│   ├── admin-guide.md                # Administrator guide
│   ├── security-model.md             # Security architecture doc
│   ├── mitre-integration.md          # ATT&CK integration guide
│   └── assets/
│       ├── banner.png
│       └── architecture-diagram.png
│
└── tests/                             # Test suites
    ├── conftest.py                    # Shared test fixtures
    ├── unit/
    │   ├── test_triage_agent.py
    │   ├── test_mitre_service.py
    │   ├── test_correlation_engine.py
    │   ├── test_nl_query_chain.py
    │   └── test_ingestion_parsers.py
    ├── integration/
    │   ├── test_api_alerts.py
    │   ├── test_api_incidents.py
    │   └── test_elasticsearch.py
    └── e2e/
        └── test_full_triage_flow.py
```

---

## 🧰 Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **LLM Inference** | Ollama + Llama 3 | Local, private LLM serving |
| **LLM Orchestration** | LangChain 0.2+ | Agent framework, chains, tools, memory |
| **Backend API** | Python FastAPI | High-performance async REST API |
| **SIEM Storage** | Elasticsearch 8.x | Event indexing, search, aggregations |
| **Log Ingestion** | OpenSearch-compatible (Logstash/Fluent Bit) | SIEM pipeline compatibility |
| **Threat Framework** | MITRE ATT&CK (STIX/TAXII) | TTP classification and enrichment |
| **Vector Store** | FAISS / ChromaDB | Semantic search and RAG |
| **Frontend** | React 18 + TypeScript + Vite | Modern analyst UI |
| **State Management** | Zustand | Lightweight frontend state |
| **Real-time** | WebSockets (FastAPI) | Live alert streaming |
| **Containerization** | Docker + Docker Compose | Deployment orchestration |
| **Auth** | JWT + FastAPI Security | Role-based access control |
| **Data Validation** | Pydantic v2 | Strict schema validation |

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| Docker | 24.x+ | With Compose v2 |
| Python | 3.11+ | Backend development |
| Node.js | 20 LTS | Frontend development |
| Ollama | Latest | Must be installed separately |
| RAM | 16 GB | 32 GB recommended for Llama 3 8B |
| Disk | 50 GB | For ES indices and model weights |

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/sentinel-ai.git
cd sentinel-ai
```

### 2. Pull the LLM Model

```bash
# Install Ollama from https://ollama.com
ollama pull llama3          # 8B model (~4.7 GB)
# or for better reasoning:
ollama pull llama3:70b      # 70B model (~40 GB, requires 64 GB RAM)
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Start All Services

```bash
docker-compose up -d
```

### 5. Initialize Elasticsearch Indices

```bash
docker-compose exec backend python -m scripts.init_indices
```

### 6. Access the Platform

| Service | URL | Credentials |
|---------|-----|-------------|
| Sentinel-AI Dashboard | http://localhost:3000 | admin / changeme |
| FastAPI Docs | http://localhost:8000/docs | — |
| Elasticsearch | http://localhost:9200 | elastic / changeme |
| Kibana (optional) | http://localhost:5601 | elastic / changeme |

---

## ⚙️ Configuration

Key environment variables (see `.env.example` for full list):

```env
# LLM Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3
OLLAMA_TEMPERATURE=0.1

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
ELASTICSEARCH_ALERT_INDEX=sentinel-alerts
ELASTICSEARCH_EVENT_INDEX=sentinel-events

# MITRE ATT&CK
MITRE_ATTACK_STIX_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
MITRE_LOCAL_CACHE_PATH=./data/mitre-attack.json

# Security
SECRET_KEY=your-256-bit-secret-key
JWT_EXPIRY_HOURS=8
CORS_ORIGINS=http://localhost:3000

# Vector Store
VECTOR_STORE_TYPE=faiss        # faiss | chroma
VECTOR_STORE_PATH=./data/vectorstore
EMBEDDING_MODEL=nomic-embed-text
```

---

## 📡 API Reference

### Core Endpoints

```
POST   /api/v1/alerts/ingest          Ingest raw security event
GET    /api/v1/alerts/                List alerts (paginated, filtered)
GET    /api/v1/alerts/{id}            Get alert details
POST   /api/v1/alerts/{id}/triage     Trigger AI triage for alert
PUT    /api/v1/alerts/{id}/status     Update alert status

GET    /api/v1/incidents/             List incidents
POST   /api/v1/incidents/             Create incident
GET    /api/v1/incidents/{id}         Get incident details
POST   /api/v1/incidents/{id}/report  Generate incident report

POST   /api/v1/query/natural          NL-to-DSL query translation
POST   /api/v1/query/execute          Execute pre-built ES query

GET    /api/v1/mitre/tactics          List all ATT&CK tactics
GET    /api/v1/mitre/techniques       List techniques (filterable by tactic)
POST   /api/v1/mitre/map              Map alert text to ATT&CK TTPs

POST   /api/v1/chat/message           Send message to analyst copilot
GET    /api/v1/chat/history/{session} Get conversation history
DELETE /api/v1/chat/session/{session} Clear session memory

WS     /ws/alerts                     Real-time alert stream
WS     /ws/chat/{session}             Real-time copilot stream
```

---

## 🗺️ Future Roadmap

### Phase 1 — Foundation ✅ *(Current)*
- [x] Project scaffold and documentation
- [ ] Core FastAPI backend with authentication
- [ ] Elasticsearch integration and index templates
- [ ] Basic LangChain agent with Ollama/Llama 3
- [ ] MITRE ATT&CK lookup tool
- [ ] Alert ingestion API
- [ ] React dashboard skeleton

### Phase 2 — Core Intelligence 🔄 *(Q3 2026)*
- [ ] Full triage agent with confidence scoring
- [ ] NL-to-DSL query translation chain
- [ ] OpenSearch-compatible log ingestion pipeline
- [ ] ATT&CK matrix heatmap visualization
- [ ] Entity relationship graph (D3.js)
- [ ] Session-based analyst memory
- [ ] Basic incident report generator

### Phase 3 — Advanced Correlation 📅 *(Q4 2026)*
- [ ] Multi-stage campaign correlation engine
- [ ] Behavioral baseline anomaly detection
- [ ] IOC enrichment integrations (OTX, MISP, VirusTotal)
- [ ] Automated false-positive suppression model
- [ ] PDF report export with executive summary
- [ ] Analyst feedback loop for RLHF fine-tuning
- [ ] Multi-model support (Mistral, Phi-3)

### Phase 4 — Automation & Orchestration 📅 *(Q1 2027)*
- [ ] SOAR integration (TheHive, Shuffle, n8n)
- [ ] Automated playbook execution
- [ ] Bi-directional ticketing system integration (Jira, ServiceNow)
- [ ] Custom detection rule suggestions from LLM
- [ ] Sigma rule auto-generation from analyst investigations
- [ ] Scheduled threat hunting queries
- [ ] Multi-tenant support

### Phase 5 — Enterprise Scale 📅 *(Q2 2027)*
- [ ] Kubernetes deployment manifests (Helm charts)
- [ ] Horizontal scaling for Elasticsearch cluster
- [ ] Multi-site federation support
- [ ] Custom LLM fine-tuning pipeline on organization-specific data
- [ ] Compliance reporting (SOC2, ISO 27001, NIST)
- [ ] TAXII 2.1 server for threat intel sharing
- [ ] Full audit trail and chain-of-custody logging

---

## 🔐 Security Considerations

> **This is a security platform. Its own security posture is non-negotiable.**

- **All LLM inference is local** — Llama 3 runs entirely via Ollama on your infrastructure. No security events, logs, or analyst queries are sent to external APIs.
- **Least-privilege RBAC** — Analyst, Senior Analyst, Incident Commander, and Admin roles with granular endpoint permissions.
- **Audit logging** — Every AI inference, query, alert status change, and user action is immutably logged in Elasticsearch.
- **Prompt injection protection** — All user inputs are sanitized before being included in LLM prompts. Structured output parsing prevents prompt injection from alert content.
- **Network isolation** — Designed for deployment in isolated network segments. Docker Compose network policies enforce inter-service communication boundaries.
- **Secret management** — No hardcoded credentials. All secrets via environment variables or HashiCorp Vault integration.
- **TLS enforcement** — All external-facing endpoints require TLS in production. See `docs/deployment-guide.md` for certificate configuration.

---

## 🤝 Contributing

Contributions are welcome from security engineers, ML practitioners, and frontend developers.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m 'feat: add your feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for code style guidelines, testing requirements, and the review process.

### Commit Convention

```
feat:     New feature
fix:      Bug fix
docs:     Documentation only
security: Security-related change
refactor: Code restructuring
test:     Adding/updating tests
chore:    Build, CI, dependencies
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [MITRE ATT&CK®](https://attack.mitre.org) — The foundational threat framework powering Sentinel-AI's TTP classification
- [LangChain](https://langchain.com) — LLM orchestration framework
- [Ollama](https://ollama.com) — Local LLM serving infrastructure
- [Meta Llama 3](https://ai.meta.com/llama/) — Open-weight language model
- [Elastic](https://elastic.co) — Search and observability platform
- The open-source SOC and threat intelligence community

---

<div align="center">

**Built for defenders, by defenders.**

*Sentinel-AI is not affiliated with MITRE, Elastic, Meta, or Ollama.*

</div>
