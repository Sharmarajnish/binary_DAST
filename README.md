
  # 🛡️ ECU Sentinel DAST
  ### Advanced Automotive Binary Security & AI-Powered Vulnerability Analysis
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
  [![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react)](https://reactjs.org/)
  [![Gemini AI](https://img.shields.io/badge/AI-Gemini%202.0-blueviolet)](https://deepmind.google/technologies/gemini/)
  [![JLR WP2 Compliant](https://img.shields.io/badge/Compliance-JLR%20WP2-green)](https://www.jaguarlandrover.com/)
</div>

---

## 🚀 Overview

**ECU Sentinel DAST** is a state-of-the-art Dynamic Application Security Testing (DAST) platform specifically engineered for the automotive industry. It combines traditional binary analysis with **Precogs AI (Gemini 2.0 Flash)** to detect, validate, and remediate critical vulnerabilities in ECU firmware and source code.

Designed to meet the rigorous standards of modern vehicle cybersecurity, it provides end-to-end visibility from repository cloning to compliance-ready reporting.

## ✨ Key Features

- **🔍 Multi-Format Binary Analysis**: Native support for automotive formats including **VBF, ARXML, Intel HEX, S-Record, ELF**, and RAW binaries.
- **🧠 AI-Powered Triage**: Integrated with **Gemini 2.0 Flash** for automated vulnerability validation and high-fidelity remediation guidance.
- **📋 Compliance-First Reporting**: Automated mapping to **JLR WP2, UNECE R155, ISO 21434, ISO 26262**, and **MISRA C:2012**.
- **📦 SBOM Generation**: Automated **CycloneDX (v1.5)** Software Bill of Materials generation for full supply chain transparency.
- **🔄 Git Integration**: Seamlessly clone and scan private or public repositories from **GitHub** and **GitLab**.
- **📊 Rich Visualization**: Interactive dashboards for monitoring compliance scores, risk trends, and vulnerability distribution.

## 🛠️ Tech Stack

- **Frontend**: React 19, Vite 6, Recharts, Lucide React, Tailwind CSS.
- **Backend**: FastAPI (Python 3.12), Uvicorn, Pydantic v2.
- **AI Engine**: Google Generative AI (Gemini 2.0 Flash).
- **Security**: SARIF 2.1.0 Export, CycloneDX SBOM.

## 🚦 Getting Started

### Prerequisites

- **Node.js**: v18+ 
- **Python**: v3.12+
- **Gemini API Key**: Obtain from [Google AI Studio](https://aistudio.google.com/)

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Sharmarajnish/binary_DAST.git
   cd binary_DAST
   ```

2. **Frontend Setup**:
   ```bash
   npm install
   ```

3. **Backend Setup**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

### Running Locally

1. **Start Backend Server**:
   ```bash
   cd backend
   python3 main.py
   # Server will run on http://localhost:8000
   ```

2. **Start Frontend Server**:
   ```bash
   # In the root directory
   npm run dev
   # App will be available at http://localhost:3000
   ```

## 📂 Project Structure

```text
├── backend/                # FastAPI Application
│   ├── dast/               # Core Security Engines
│   ├── uploads/            # Temporary storage for scans
│   └── main.py             # API Entry Point
├── components/             # React UI Components
├── services/               # Frontend API Services
├── examples/               # Sample Automotive Binaries
└── App.tsx                 # Main UI Logic
```

---

<div align="center">
  <p>Built for Scale • Built for Security • Built for Automotive</p>
  <sub>© 2025 Precogs AI | Leading the Future of ECU Cybersecurity</sub>
</div>
