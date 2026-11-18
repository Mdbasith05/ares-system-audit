# ARES — System Telemetry & Endpoint Investigation Lab

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6.svg?logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![Architecture](https://img.shields.io/badge/Architecture-Clean%20Telemetry%20Pipeline-success.svg)](#architecture)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-orange.svg)](#design-principles)

> **A lightweight, forensic-grade Windows telemetry and endpoint investigation workbench.**  
> Built strictly with Python's standard library and native Windows APIs to audit active processes, inspect live TCP sockets, analyze Windows Event Logs, and export cryptographic SHA-256 evidence packages — with zero cloud telemetry leakage.

---

## 🚀 Key Architectural Capabilities

### 1. Windows Event Log Forensic Ingestion
- Ingests and parses records from **Windows Security**, **System**, **Application**, and **PowerShell Operational** event streams.
- Configurable time-window filtering (*Past 1 hour, 6 hours, 24 hours, 7 days*).
- Identifies critical operational and security event IDs (e.g., failed logon anomalies, service creation events, process executions).

### 2. Live Network & Socket Telemetry
- Point-in-time snapshot of active **TCP connections**, remote endpoints, and process ownership.
- Audits listening ports, bound interfaces, and DNS client resolution caches.
- Correlates network sockets directly to originating Windows Process IDs (PIDs).

### 3. Forensic Integrity & Cryptographic Packaging
- Writes collections to structured JSON Lines (`.jsonl`) evidence files under `%LOCALAPPDATA%\CybersecurityOperationsLab\`.
- Automatically computes **SHA-256 cryptographic digests** for every captured evidence stream in `manifest.json`.
- Guarantees read-only operation: original Windows logs and system registries remain unaltered.

### 4. Interactive Analyst Workbench GUI
- Native, modern desktop interface built with Python Tkinter/TTK.
- **Overview:** Real-time summary cards, available telemetry streams, and heuristic pattern observations.
- **Evidence Explorer:** Deep-search loaded records by source, technical fields, or regex message matching.
- **Investigations Journal:** Separates observed facts from analyst hypotheses and next evidence targets.

---

## 🛠️ Architecture & Data Pipeline

```
+------------------------------------------------------------------------+
|                      ARES Telemetry Workbench                          |
+------------------------------------------------------------------------+
        |                                                |
        v                                                v
[ Windows API & Event Logs ]                     [ Endpoint Telemetry ]
  • windows.security                               • network.connections (TCP)
  • windows.system                                 • network.listeners (Sockets)
  • windows.application                            • system.processes (Active PIDs)
  • windows.powershell                             • network.dns_cache
        |                                                |
        +-----------------------+------------------------+
                                |
                                v
               [ Structured Ingestion & Normalizer ]
                                |
        +-----------------------+------------------------+
        |                                                |
        v                                                v
[ Local Cryptographic Storage ]               [ Interactive Analyst GUI ]
  • Evidence JSON Lines (.jsonl)                 • Overview & Source Cards
  • SHA-256 Manifest (manifest.json)             • Evidence Deep-Search Filter
  • Investigation Case Notes                     • Observation Pattern Analyzer
```

---

## 💻 Tech Stack & Design Principles

- **Core Engine:** Python 3.10+ (Standard Library: `hashlib`, `json`, `subprocess`, `threading`, `queue`, `pathlib`).
- **GUI Framework:** Native `tkinter` / `ttk` with custom high-contrast dark palette styling.
- **Operating System Integration:** Windows Management Instrumentation (WMI), Win32 API endpoints, and `pktmon` diagnostic captures.
- **Zero Cloud Dependence:** 100% on-device data processing. No telemetry or private endpoints leave the local machine.

---

## 🏃 Quick Start

### Prerequisites
- Windows 10, Windows 11, or Windows Server 2016+
- Python 3.10 or higher installed

### Run Locally
```powershell
# Clone the repository
git clone https://github.com/Mdbasith05/ares-system-audit.git
cd ares-system-audit

# Launch the Workbench directly (or double click 'Start Local Telemetry Lab.bat')
python local_lab.py
```

---

## 👤 Author

**Mohammed Basith**  
*Computer Science Graduate (2026) • Systems Infrastructure & Software Engineer*  
- **LinkedIn:** [linkedin.com/in/mohammedbasith05](https://www.linkedin.com/in/mohammedbasith05)  
- **GitHub:** [github.com/Mdbasith05](https://github.com/Mdbasith05)  
- **Email:** [mohammedbasith490@gmail.com](mailto:mohammedbasith490@gmail.com)  
- **Location:** Chennai, India (Ready for Immediate Relocation to Dubai / UAE on Visit Visa)
