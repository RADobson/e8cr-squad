# Essential Eight ML2 Requirements — Patch Applications & Patch OS

Source: [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model)

## Patch Applications — Maturity Level 2

### Asset Discovery
- An automated method of asset discovery is used **at least fortnightly** to support the detection of assets for subsequent vulnerability scanning activities.

### Vulnerability Scanning
- A vulnerability scanner is used **at least fortnightly** to identify missing patches or updates for vulnerabilities in:
  - Office productivity suites, web browsers and their extensions, email clients, PDF software, and security products on **endpoints and servers**
  - Other applications on **endpoints and servers**

### Patching Timelines
- Patches, updates or other vendor mitigations for vulnerabilities in **internet-facing services** are applied:
  - Within **48 hours** of release when vulnerabilities are assessed as critical by vendors or when working exploits exist
  - Within **2 weeks** of release otherwise

- Patches, updates or other vendor mitigations for vulnerabilities in **office productivity suites, web browsers and their extensions, email clients, PDF software, and security products** on endpoints and servers are applied:
  - Within **48 hours** of release when vulnerabilities are assessed as critical by vendors or when working exploits exist
  - Within **2 weeks** of release otherwise

- Patches, updates or other vendor mitigations for vulnerabilities in **other applications** on endpoints and servers are applied within **1 month** of release.

### Unsupported Software
- Applications that are **no longer supported by vendors** are removed.

## Patch OS — Maturity Level 2

### Asset Discovery
- An automated method of asset discovery is used **at least fortnightly** to support the detection of assets for subsequent vulnerability scanning activities.

### Vulnerability Scanning
- A vulnerability scanner is used **at least fortnightly** to identify missing patches or updates for vulnerabilities in operating systems of **endpoints and servers**.

### Patching Timelines
- Patches, updates or other vendor mitigations for vulnerabilities in operating systems of **internet-facing services** are applied:
  - Within **48 hours** of release when vulnerabilities are assessed as critical by vendors or when working exploits exist
  - Within **2 weeks** of release otherwise

- Patches, updates or other vendor mitigations for vulnerabilities in operating systems of **endpoints and servers** are applied:
  - Within **48 hours** of release when vulnerabilities are assessed as critical by vendors or when working exploits exist
  - Within **2 weeks** of release otherwise

### Unsupported Operating Systems
- Operating systems that are **no longer supported by vendors** are removed.

## Key Definitions

- **Critical by vendors:** The vendor has assessed the vulnerability as critical severity (e.g., Microsoft "Critical" rating).
- **Working exploits exist:** There is publicly available exploit code, OR the vulnerability appears on the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Internet-facing services:** Services accessible from the internet (web servers, email gateways, VPN endpoints, etc.).
- **Endpoints:** User workstations — laptops, desktops.
- **Servers:** Infrastructure servers — file servers, domain controllers, application servers.

## Evidence Requirements for Assessment

An assessor will look for:
1. **Asset inventory** — complete list of managed devices with OS and application versions
2. **Scan records** — proof that vulnerability scanning occurs at least fortnightly
3. **Patch deployment records** — timestamps showing patches were deployed within required timelines
4. **Verification records** — proof that patches were successfully applied (not just deployed)
5. **Exception register** — any devices or software that deviate from standard, with justification
6. **Unsupported software register** — tracking of end-of-life software and removal plans
