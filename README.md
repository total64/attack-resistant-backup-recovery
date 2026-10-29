# ARBR: Attack-Resistant Backup and Recovery System

**Detect the Threat. Protect the Backup. Recover with Confidence.**

ARBR is a cybersecurity system designed to help organizations detect suspicious file activity, analyze risks, protect backup data, and support controlled recovery from ransomware and other destructive cyberattacks.

**[Live Dashboard](https://arbr.onrender.com/) | [GitHub Repository](https://github.com/total64/attack-resistant-backup-recovery)**

---

## Overview

Ransomware can encrypt or destroy important files and target backup systems, making recovery difficult. ARBR explores how threat detection, risk analysis, backup integrity verification, isolation, and recovery can work together to reduce the risk of permanent data loss.

The project brings these defensive capabilities into a unified workflow, helping users monitor security events and manage backup and recovery operations.

## Key Features

- **Threat Detection:** Collect and process security alerts from integrated monitoring tools.
- **Risk Analysis:** Evaluate potential threats and help prioritize security events.
- **Backup Management:** Track backup operations and their status.
- **System Isolation:** Support containment of affected systems through configured controls.
- **Integrity Verification:** Check backup integrity before recovery.
- **Recovery Management:** Support controlled recovery workflows.
- **Audit Logging:** Record security events and operation results.
- **Access Control:** Restrict sensitive operations according to configured permissions.
---

*Built with collaboration, creativity, and a shared passion for technology.*


## System Workflow

```text
Security Monitoring
        |
        v
Threat Detection
        |
        v
Risk Analysis
        |
        v
Backup Protection
        |
        v
System Isolation
        |
        v
Integrity Verification
        |
        v
Controlled Recovery
        |
        v
Audit and Reporting
```

The workflow supports a structured response to suspicious activity. Actual actions depend on the system configuration, available integrations, and required authorization.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite |
| Backend | Python, FastAPI |
| Security Monitoring | Wazuh |
| System Operations | Linux, SSH, backup and recovery utilities |
| Security Functions | Risk analysis, integrity verification, isolation, and recovery |

## Requirements

A complete deployment may require:

- Python and the project's backend dependencies
- Node.js and npm
- A supported Linux environment for system-level operations
- A configured Wazuh server and agents for security monitoring
- Appropriate environment variables, permissions, and service configurations

Refer to the project's dependency files and configuration for the exact versions and setup requirements.

## Getting Started

Clone the repository:

```bash
git clone https://github.com/total64/attack-resistant-backup-recovery.git
cd attack-resistant-backup-recovery
```

Install the backend and frontend dependencies according to the project's configuration. Configure the required environment variables and services before starting the application.

For complete setup instructions, use the dependency files and configuration included in the repository.

## Testing

The project includes tests for important backend functionality, including risk analysis, integrity verification, and recovery-related operations.

Run the tests using the project's configured Python environment and test instructions.

## Security Considerations

- Restrict access to sensitive operations.
- Verify backup integrity before recovery.
- Configure isolation and recovery permissions carefully.
- Protect credentials, API tokens, and environment files.
- Test recovery procedures in an authorized environment.
- Regularly verify that backups can be restored successfully.

## Project Goal

ARBR demonstrates how threat detection, risk-based decisions, backup protection, and verified recovery can work together to improve resilience against ransomware and other destructive cyberattacks.

---
# Our Team

Meet the people behind this project.

| No. | Name | CTC ID | GitHub |
|---:|---|---|---|
| 1 | Naboni Abrham | CTC-459-26 | [@naboni-git](https://github.com/naboni-git) |
| 2 | Lameik Equar | CTC-3115-26 | [@captlameik](https://github.com/captlameik) |
| 3 | Befikir Shimelis | CTC-674-26 | [@squidward404](https://github.com/squidward404) |
| 4 | Eden Mulugeta | CTC-4135-26 | [@girlcode-eden](https://github.com/girlcode-eden) |
| 5 | Abenezer Tekalign | CTC-7212-26 | [@Abeni118](https://github.com/Abeni118) |
| 6 | Naaol Raffisaa | CTC-1138-26 | [@total64](https://github.com/total64) |

---

*Built with collaboration, creativity, and a shared passion for technology.*

---

**ARBR | Protecting Data. Strengthening Recovery.**

[Live Dashboard](https://arbr.onrender.com/) · [Source Code](https://github.com/total64/attack-resistant-backup-recovery)
