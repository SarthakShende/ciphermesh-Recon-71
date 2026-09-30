# CipherMesh — Hardware-Rooted Decentralized IoT Trust Network

> **SIH 2026 | Problem Statement 26211 | Blockchain & Cybersecurity**

CipherMesh is a decentralized IoT security platform that connects physical sensors to a hardware-rooted trust system. A sensor event is created by a Raspberry Pi, cryptographically signed, transported over **Reticulum + LoRa**, verified by another edge node, synchronized to a cloud backend when connectivity is available, analysed for abnormal behaviour, and selectively anchored as evidence on a distributed ledger.

The goal is simple:

**Prove that an IoT event came from a trusted device, verify it even during connectivity disruptions, detect suspicious behaviour, and preserve important security evidence in a tamper-evident distributed record.**

---

## 1. Problem Statement

### SIH 2026 — PS 26211

**Student Innovation — Decentralized and Distributed Ledger Technology for Secure Digital Information and Multi-Sector Applications.**

CipherMesh applies decentralized ledger technology to a practical IoT security problem: establishing trustworthy device identity and verifiable event history in environments where devices may be remote, bandwidth-limited, intermittently connected, or exposed to physical tampering.

---

## 2. What CipherMesh Does

CipherMesh creates a trust chain between the **physical world** and the **digital evidence layer**.

```text
Temperature Sensor
        │
        ▼
 Raspberry Pi A
 Sensor + Gateway
        │
        ▼
 Hardware Device Identity
        │
        ▼
 SHA-256 + Ed25519
 Signed Sensor Event
        │
        ▼
 Reticulum + LoRa
        │
        ▼
 Raspberry Pi B
 Receiver + Monitor
        │
        ▼
 Signature / Hash / Sequence /
 Freshness / Replay Verification
        │
        ▼
 Trust + Behaviour Analysis
        │
        ▼
 FastAPI Backend
        │
   ┌────┴───────────────┐
   ▼                    ▼
Supabase             DLT Layer
Auth + Database      Evidence
   │                    │
   └────────┬───────────┘
            ▼
       Next.js Dashboard
```

### Core idea

> **Physical Event → Hardware Identity → Signed Event → Reticulum + LoRa → Verification → Trust Decision → DLT Evidence**

---

## 3. Why It Is Different

CipherMesh does not claim to invent LoRa, Reticulum, blockchain, AI, or cryptography individually.

The innovation is their integration into a single IoT trust architecture:

- **Hardware-rooted identity** for physical devices
- **Cryptographically signed sensor events**
- **Offline-capable event transport** using Reticulum + LoRa
- **Local verification and buffering** when the Internet is unavailable
- **Replay and tamper detection**
- **AI-assisted behavioural analysis**
- **Cryptography remains authoritative over AI**
- **Selective DLT anchoring** for important security evidence

This makes the system useful for remote and disruption-prone IoT deployments.

---

# 4. Current MVP Hardware

The current prototype uses **two Raspberry Pi 4B nodes**.

## Pi A — Gateway + Temperature Sensor

Responsibilities:

- Read temperature
- Maintain device identity
- Generate sensor events
- Hash events with SHA-256
- Sign events with Ed25519
- Send events through Reticulum + LoRa
- Buffer events when cloud connectivity is unavailable
- Synchronize with the backend when connectivity returns

## Pi B — Receiver + Monitor

Responsibilities:

- Receive events through Reticulum + LoRa
- Verify device identity
- Verify event signature
- Verify event hash
- Check sequence number
- Check event freshness
- Detect replayed events
- Check device revocation state
- Store verified/rejected events locally
- Provide monitoring information to a laptop
- Synchronize relevant events with the backend

Both Pis use the **same edge codebase**. The role is selected during setup.

---

# 5. Architecture

## 5.1 Edge Layer

```text
Pi A
├── Temperature Sensor
├── Device Identity
├── SHA-256
├── Ed25519 Signing
├── Reticulum
└── LoRa

             ⇅

Pi B
├── Reticulum
├── LoRa
├── Signature Verification
├── Replay Detection
├── Freshness Checks
├── Revocation Checks
└── SQLite
```

## 5.2 Cloud Layer

```text
Raspberry Pi
      │
      │ HTTPS/TLS
      ▼
FastAPI Backend
      │
      ├── Device Service
      ├── Event Service
      ├── Verification Service
      ├── Trust Engine
      ├── AI Engine
      ├── Gateway Service
      └── DLT Adapter
             │
       ┌─────┴─────┐
       ▼           ▼
   Supabase       DLT
   Auth + DB      Evidence
```

## 5.3 Frontend

```text
Next.js + TypeScript + Tailwind
              │
              │ HTTPS
              ▼
        FastAPI Backend
```

The web application is intended to run on **Vercel** and the FastAPI backend on **Render**.

---

# 6. Main Trust Flow

### Step 1 — Physical event

The temperature sensor produces a real measurement.

### Step 2 — Event creation

Pi A creates a canonical event containing fields such as:

```text
event_id
device_id
event_type
value
unit
timestamp
sequence
firmware_hash
event_version
```

### Step 3 — Cryptographic protection

The event is hashed using **SHA-256** and signed using **Ed25519**.

### Step 4 — Offline-capable transport

The signed event is sent through:

```text
Reticulum
   ↓
LoRa
```

No continuous Internet connection is required for Pi-to-Pi communication.

### Step 5 — Verification

Pi B checks:

- Device identity
- Signature
- Event hash
- Sequence number
- Freshness
- Duplicate/replay status
- Device revocation state

### Step 6 — Trust analysis

Verified events contribute to the device trust state.

Behavioural analysis can identify unusual activity.

### Step 7 — Cloud synchronization

When Internet is available, verified events and security events are synchronized with the FastAPI backend.

When Internet is unavailable, events remain in the local queue.

### Step 8 — DLT evidence

Important security evidence can be selectively anchored to the distributed ledger.

Raw telemetry is not placed on-chain.

---

# 7. Offline-First Operation

A major part of CipherMesh is that the edge network should continue operating during Internet outages.

### Internet available

```text
Sensor
 ↓
Pi A
 ↓
LoRa
 ↓
Pi B
 ↓
Local Verification
 ↓
FastAPI
 ↓
Supabase / DLT
 ↓
Dashboard
```

### Internet unavailable

```text
Sensor
 ↓
Pi A
 ↓
LoRa
 ↓
Pi B
 ↓
Local Verification
 ↓
SQLite + Sync Queue
```

When connectivity returns:

```text
Sync Queue
    ↓
Retry
    ↓
FastAPI
    ↓
Database / DLT
```

The system must not discard valid events simply because the cloud is temporarily unreachable.

---

# 8. Security Model

## Device identity

Every device has its own cryptographic identity.

The device private key:

- stays on the device
- is protected with restrictive permissions
- is never transmitted over LoRa
- is never uploaded to the backend
- is never stored in PostgreSQL
- is never exposed to the frontend

## Event integrity

Each event is:

```text
Canonical Event
      ↓
SHA-256
      ↓
Ed25519 Signature
```

Changing the event after signing causes verification to fail.

## Replay protection

Each event contains a persistent sequence number.

The receiver checks:

- sequence progression
- timestamp/freshness
- duplicate event ID

A previously accepted event cannot simply be replayed as a new valid event.

## Revocation

A compromised or decommissioned device can be revoked.

Future events from a revoked device are rejected.

## AI security boundary

AI is advisory.

AI cannot:

- approve an invalid signature
- restore a revoked device
- bypass firmware verification
- override cryptographic failure

**Cryptographic verification remains authoritative.**

---

# 9. DLT / Blockchain Design

CipherMesh uses DLT as an **evidence layer**, not as a replacement for the database or communication network.

### Suitable evidence

- Device identity references
- Public-key references
- Firmware hashes
- Important event hashes
- Security event hashes
- Device status
- Revocation state
- Trusted history references

### Kept off-chain

- Raw sensor telemetry
- Private keys
- Passwords
- Detailed AI feature data
- Large payloads
- Unnecessary personal information

The DLT implementation is isolated behind a backend adapter so the project can support either an **EVM-compatible DLT or a permissioned DLT** without redesigning the frontend.

---

# 10. AI / Behaviour Analysis

The AI layer answers a different question from cryptography.

### Cryptography asks:

> "Did this event really come from the device that signed it?"

### Behaviour analysis asks:

> "Is this authenticated device behaving normally?"

Possible signals include:

- Event frequency
- Heartbeat frequency
- Failed verification attempts
- Unexpected communication patterns
- Repeated failures
- Unusual device state transitions
- Tamper/security events

For the MVP, explainable rules, statistical baselines, or lightweight anomaly detection are preferred over unnecessarily complex models.

---

# 11. Software Stack

| Layer | Technology |
|---|---|
| Edge hardware | Raspberry Pi 4B |
| Sensor | Temperature sensor |
| Radio | LoRa |
| Networking | Reticulum Network Stack |
| Event hashing | SHA-256 |
| Event signing | Ed25519 |
| Edge storage | SQLite |
| Backend | Python + FastAPI |
| Authentication | Supabase Auth |
| Cloud database | Supabase PostgreSQL |
| AI | Explainable anomaly detection |
| DLT | Adapter-based EVM/permissioned design |
| Frontend | Next.js + TypeScript + Tailwind CSS |
| Frontend hosting | Vercel |
| Backend hosting | Render |

---

# 12. Repository Structure

The project is intentionally separated into two codebases.

```text
sihf/
│
├── pi4/
│   ├── setup.sh
│   ├── setup.md
│   ├── pyproject.toml
│   ├── requirements.txt
│   ├── src/
│   ├── tests/
│   ├── config/
│   └── systemd/
│
└── web4/
    ├── app/
    ├── components/
    ├── hooks/
    ├── lib/
    ├── types/
    ├── public/
    ├── package.json
    ├── .env.example
    └── README.md
```

### Why two codebases?

`pi4/` contains edge/hardware code.

`web4/` contains the web frontend and cloud-facing application.

This prevents hardware dependencies from being mixed with the web application.

---

# 13. Quick Setup for Judges

The recommended judge flow is:

```text
1. Clone repository
2. Set up Pi A
3. Set up Pi B
4. Configure LoRa
5. Start edge services
6. Start FastAPI backend
7. Configure Supabase
8. Start Next.js frontend
9. Connect Pi A → Pi B
10. Run the demo
```

## Step 1 — Clone

```bash
git clone <REPOSITORY_URL>
cd sihf
```

> Replace `<REPOSITORY_URL>` with the project's actual repository URL.

---

# 14. Raspberry Pi Setup

Go to the edge project:

```bash
cd pi4
```

The complete Raspberry Pi installation and configuration instructions are maintained in:

**[`pi4/setup.md`](pi4/setup.md)**

This document should be treated as the detailed hardware setup guide.

It covers:

- Raspberry Pi prerequisites
- Python environment
- dependencies
- device role selection
- device identity
- Reticulum configuration
- LoRa configuration
- local storage
- systemd services
- health checks
- troubleshooting
- cloud configuration

### Install

```bash
chmod +x setup.sh
sudo ./setup.sh
```

During installation select:

```text
1. Gateway + Temperature Sensor
2. Receiver + Monitoring
```

Configure Pi A as:

```text
Gateway + Temperature Sensor
```

Configure Pi B as:

```text
Receiver + Monitoring
```

### Important

The exact LoRa configuration depends on the physical LoRa hardware being used.

Do not use an invented frequency, driver, or interface configuration.

Refer to:

**[`pi4/setup.md`](pi4/setup.md)**

for the hardware-specific configuration.

---

# 15. Frontend Setup

Go to:

```bash
cd web4
```

Install dependencies:

```bash
npm install
```

Create:

```text
.env.local
```

based on:

```text
.env.example
```

Typical configuration:

```env
NEXT_PUBLIC_SUPABASE_URL=...
NEXT_PUBLIC_SUPABASE_ANON_KEY=...
NEXT_PUBLIC_API_BASE_URL=...
```

Start development server:

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

Production validation:

```bash
npm run lint
npm run build
```

---

# 16. Backend Setup

The FastAPI backend is responsible for cloud integration.

Expected responsibilities:

- Device registration
- Event ingestion
- Event verification
- Security event storage
- Trust state
- AI anomaly processing
- Gateway heartbeat
- Device revocation
- DLT evidence
- Cloud synchronization

Example API structure:

```text
/api/v1/devices
/api/v1/events
/api/v1/security-events
/api/v1/anomalies
/api/v1/trust
/api/v1/gateway
/api/v1/network
/api/v1/dlt-evidence
```

The frontend communicates with the backend through HTTPS.

---

# 17. Supabase Setup

Supabase provides:

### Authentication

Human users log into the dashboard through Supabase Auth.

### PostgreSQL

The backend stores application data such as:

- Devices
- Public-key metadata
- Events
- Security events
- Anomaly results
- Trust states
- Gateway information
- DLT transaction references

### Important security rule

Do not store device private keys in Supabase.

Do not expose Supabase service credentials in the frontend.

Use Row Level Security and backend authorization appropriately.

---

# 18. Complete Demo

## Normal event

```text
Temperature Sensor
       ↓
Pi A
       ↓
SHA-256 + Ed25519
       ↓
Reticulum + LoRa
       ↓
Pi B
       ↓
Verification
       ↓
FastAPI
       ↓
Supabase
       ↓
DLT Evidence
       ↓
Dashboard
```

Expected result:

```text
Event: VALID
Device: TRUSTED
Signature: VERIFIED
Replay: NO
Cloud: SYNCED
```

---

## Replay attack

Send the same event again.

Expected:

```text
REPLAY_REJECTED
```

The dashboard should show the security event.

---

## Tampered event

Modify the event after signing.

Expected:

```text
INVALID_SIGNATURE
```

The event must not become trusted.

---

## Internet outage

Disconnect Internet from the edge network.

Expected:

```text
Sensor → Pi A → LoRa → Pi B
```

continues working.

Events are stored locally.

The sync queue grows.

Restore Internet.

Expected:

```text
Local Queue
     ↓
Automatic Sync
     ↓
Backend
```

---

## Device revocation

Revoke a device from the security interface.

Expected:

```text
Device = REVOKED
Future events = REJECTED
```

---

## AI anomaly

Generate an unusual event pattern.

Expected:

```text
Behaviour anomaly detected
```

The system explains why the event/device behaviour is considered unusual.

AI does not override cryptographic verification.

---

# 19. Judge-Friendly Demonstration Order

For an SIH presentation, demonstrate the system in this order:

### 1. Show the dashboard

Show:

- Devices
- Network
- Temperature
- Recent events
- Trust state

### 2. Show the physical hardware

```text
Pi A + Temperature Sensor + LoRa
Pi B + LoRa + Laptop
```

### 3. Generate a real temperature event

Show the reading on Pi A.

### 4. Show the signed event

Explain:

```text
SHA-256 + Ed25519
```

### 5. Send through LoRa

Show the event arriving at Pi B.

### 6. Verify it

Show:

```text
Signature: Valid
Sequence: Valid
Freshness: Valid
Replay: Not detected
Device: Trusted
```

### 7. Demonstrate replay protection

Replay the same event.

Show:

```text
REPLAY_REJECTED
```

### 8. Demonstrate offline operation

Disconnect Internet.

Generate events.

Show local operation continuing.

### 9. Restore Internet

Show automatic synchronization.

### 10. Show DLT evidence

Open the DLT Evidence page and show the evidence/transaction reference.

---

# 20. Challenges and Mitigations

| Challenge | Mitigation |
|---|---|
| Bandwidth | Compact packets + local filtering |
| Connectivity | Local verification + buffered sync |
| Device compromise | Secure Boot + signed firmware + hardware keys + revocation |
| Replay attacks | Sequence + freshness checks |
| AI errors | Explainable AI; cryptography remains authoritative |
| Power usage | Optimize event frequency + measure energy/event |
| Integration | Validate Reticulum + LoRa with a multi-node prototype |
| DLT choice | Finalize EVM vs permissioned DLT during architecture phase |

---

# 21. Security Principles

CipherMesh follows these principles:

1. **Never trust an unverified device.**
2. **Never trust an unsigned event.**
3. **Never allow AI to override cryptographic security.**
4. **Never transmit private keys.**
5. **Never store private keys in the cloud.**
6. **Never use blockchain as a replacement for the database.**
7. **Never send large payloads over LoRa.**
8. **Never claim connectivity when the hardware is offline.**
9. **Never treat demo data as real hardware data.**
10. **Keep working locally when the Internet is unavailable.**

---

# 22. Limitations

The MVP is a prototype and does not claim production-scale deployment.

Current limitations include:

- Two Raspberry Pi edge nodes
- Temperature sensing as the primary physical event
- LoRa bandwidth limitations
- Exact radio performance depends on hardware and environment
- DLT selection may depend on final deployment requirements
- AI is intended as an advisory anomaly-detection layer
- Production secure-element integration may require hardware-specific implementation
- Large-scale fleet management requires additional infrastructure
- Field deployment requires regulatory, power, reliability, and security validation

These limitations are intentionally documented rather than hidden.

---

# 23. Future Expansion

CipherMesh can later support:

- More IoT sensor types
- More edge nodes
- Multi-hop deployments
- Environmental monitoring
- Agriculture
- Disaster response
- Industrial monitoring
- Infrastructure monitoring
- Hardware secure elements
- Stronger remote attestation
- Multiple gateways
- Production-grade DLT networks
- Advanced anomaly detection
- Fleet management
- Tamper-resistant enclosures

---

# 24. Project Status

### Current MVP target

```text
[x] Next.js dashboard
[x] Supabase integration foundation
[x] FastAPI architecture
[x] Raspberry Pi 4B edge architecture
[x] Two-node deployment model
[x] Reticulum + LoRa architecture
[x] Signed event architecture
[x] Offline-first design
[x] Replay protection design
[x] AI/trust architecture
[x] DLT evidence architecture
[ ] Final LoRa hardware-specific integration
[ ] Full Pi-to-Pi hardware validation
[ ] Full cloud deployment
[ ] Final DLT selection
[ ] End-to-end SIH demo validation
```

Only mark an item `[x]` in the real repository when it has actually been implemented and tested.

---

# 25. Documentation

### Hardware / Raspberry Pi

**[Open the Raspberry Pi Setup Guide](pi4/setup.md)**

This is the first document to read when setting up the physical prototype.

### Frontend

See:

```text
web4/
```

### Backend

See the backend documentation/API contract in the backend project.

### Architecture

The overall architecture is:

```text
Physical Event
      ↓
Hardware Identity
      ↓
Signed Event
      ↓
Reticulum + LoRa
      ↓
Cryptographic Verification
      ↓
Trust + AI
      ↓
FastAPI
      ↓
Supabase + DLT
      ↓
Next.js Dashboard
```

---

# 26. Quick Troubleshooting

## Pi service is not running

Check:

```bash
sudo systemctl status <ciphermesh-service>
```

Check logs:

```bash
journalctl -u <ciphermesh-service> -f
```

## Check device health

```bash
ciphermesh health
```

## Check Reticulum

```bash
ciphermesh reticulum status
```

## Check LoRa

```bash
ciphermesh lora status
```

## Check local events

```bash
ciphermesh events
```

## Check synchronization

```bash
ciphermesh sync
```

For installation and hardware-specific issues, see:

**[`pi4/setup.md`](pi4/setup.md)**

---

# 27. Repository Safety

Never commit:

```text
.env
.env.local
private keys
device identity private keys
Supabase service-role keys
API secrets
DLT private keys
local databases containing sensitive data
```

Use:

```text
.env.example
```

for configuration templates.

---

# 28. One-Line Project Explanation

> **CipherMesh is a hardware-rooted, offline-capable IoT trust network that signs physical sensor events, verifies them over Reticulum + LoRa, detects abnormal behaviour, and preserves important security evidence on a distributed ledger.**

---

# 29. Final Architecture Summary

```text
                 CIPHER MESH
       Hardware-Rooted IoT Trust Network

                    ┌───────────┐
                    │  SENSOR   │
                    └─────┬─────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │     PI A        │
                 │ Sensor+Gateway  │
                 └────────┬────────┘
                          │
                    SHA-256
                    Ed25519
                          │
                          ▼
                 ┌─────────────────┐
                 │ Reticulum+LoRa  │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │      PI B       │
                 │ Receiver+Monitor│
                 └────────┬────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
          Signature    Replay      Freshness
          Check        Check        Check
              │           │           │
              └───────────┼───────────┘
                          ▼
                 ┌─────────────────┐
                 │ Trust + AI      │
                 └────────┬────────┘
                          │
                       HTTPS
                          │
                          ▼
                 ┌─────────────────┐
                 │ FastAPI Backend  │
                 └───────┬─────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        ┌───────────┐        ┌────────────┐
        │ Supabase  │        │    DLT     │
        │ Auth + DB │        │  Evidence  │
        └─────┬─────┘        └──────┬─────┘
              │                     │
              └──────────┬──────────┘
                         ▼
                 ┌─────────────────┐
                 │ Next.js Web App │
                 │    Dashboard    │
                 └─────────────────┘
```

---

## License

Add the project's actual license here before public release.

## Team

**CipherMesh — SIH 2026**

Problem Statement: **26211**

Theme: **Blockchain & Cybersecurity**
