# Host Endpoint Protection & Defense Shield

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Endpoint Security & Host Hardening  
**Tech Stack**: `Python 3.10+ · Host Forensics · SHA-256 Verification · Windows/Linux Hardening`  

Lightweight host defense engine providing signature-based file integrity verification, malicious process termination, and host firewall rule enforcement.

---

## 🎯 The Problem It Solves

Workstations and jump boxes are frequent entry points for enterprise attacks. Organizations require lightweight, offline host defenses that do not rely on heavy proprietary agents.

---

## ⚙️ How the Engine Works

1. **File Integrity Hash Monitoring**: Computes SHA-256 cryptographic hashes of critical system binaries and configuration files, comparing against known baselines.
2. **Process Execution Inspection**: Inspects running processes, identifying suspicious execution paths (e.g. scripts executing from temporary directories or unauthorized powershell wrappers).
3. **Host Firewall Policy Enforcement**: Validates that local firewall profiles (Domain, Private, Public) are active and enforces default-deny inbound rules.
4. **Tamper Alerting**: Triggers instant defensive alerts when system files or critical registry/service configurations are altered.
5. **Containment Actions**: Emits local isolation commands and process termination requests when malicious behavior is confirmed.

---

## 🚀 Key Capabilities

- Cryptographic file integrity validation against unauthorized tampering
- Host firewall state and inbound rule posture auditing
- Detection of suspicious administrative execution chains
- Deterministic offline operation without internet connectivity required

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
