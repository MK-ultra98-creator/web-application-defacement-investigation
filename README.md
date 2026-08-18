# Web Application Defacement Investigation (startrek.com)

Short description
A Splunk-based investigation of a web application defacement incident that targeted the site referred to as `startrek.com` (placeholder). This repository contains an extracted and cleaned lab report, Splunk searches, example dashboards, indicators of compromise (IOCs), and a remediation playbook suitable for SOC analysts and incident responders.

Table of contents
- Background
- Scope & objectives
- Data sources
- Repository structure
- How to reproduce (Splunk setup)
- Methodology & Kill Chain mapping
- Key findings & timeline
- Indicators of Compromise (IOCs)
- Example Splunk searches & dashboards
- Detection & mitigation recommendations
- Playbook / Runbook
- Contributing
- License
- Contact

Background
On a public-facing web server (referred to here as `startrek.com`) a defacement was detected. The investigation used IIS and HTTP logs, network IDS alerts, and artifacts recovered from the webroot to reconstruct attacker actions and provide detection and remediation guidance.

Scope & objectives
- Reconstruct the attacker’s steps from reconnaissance through defacement.
- Provide reproducible Splunk searches and dashboard examples to detect similar attacks.
- Deliver an actionable playbook for containment, eradication, and recovery.

Data sources
- IIS access and error logs
- HTTP access logs and application logs
- Network IDS alerts (Suricata/Zeek)
- Authentication logs
- Files recovered from the webroot (uploads, modified files)

Repository structure
- README.md (this file)
- reports/ — cleaned Markdown report extracted from the original lab document
  - splunk-lab1.md — converted and edited report
- searches/ — example Splunk Processing Language (SPL) queries used in the investigation
  - upload_detection.spl
  - suspicious_auth.spl
- dashboards/ — exported dashboard examples (if available)
- artifacts/
  - images/ — extracted images/screenshots (if any)
  - extracted_uploaded_files/ — recovered uploaded files
- iocs/
  - iocs.csv — machine-readable IOCs (IP, domain, filename, hash)
- playbooks/
  - containment.md — short runbook for containment & remediation
- original/ — (optional) the original binary report archive (if retained)

How to reproduce (Splunk high-level)
1. Splunk Enterprise 8.x or Splunk Cloud.
2. Create indexes: `iis`, `http`, `ids`, `auth` (or adjust the index names in searches).
3. Ingest sample logs into the appropriate indexes (IIS logs, IDS alerts, auth logs).
4. Import saved searches and dashboards from the /searches and /dashboards folders.
5. Run the example SPL queries against your sample data to validate detection behavior.

Methodology (Lockheed Martin Cyber Kill Chain)
- Reconnaissance & scanning — identify HTTP probes and suspicious user agents.
- Target identification — repeated requests to directories, probing for upload endpoints.
- Vulnerability assessment — attempts to trigger file upload, path traversal, or arbitrary file write.
- Credential attacks — repeated failed auth attempts and credential stuffing patterns.
- Successful authentication — suspicious successful login events linked to attacker IPs.
- Malicious file upload — POSTs with multipart/form-data containing webshells or executable content.
- Web-server compromise & defacement — replacement of public files (index.html) and presence of webshells.

Key findings & timeline
See reports/splunk-lab1.md for the full, timestamped timeline and supporting evidence. Highlights:
- Recon probes observed originating from discrete external IPs targeting common upload endpoints.
- Evidence of a multipart POST resulting in new PHP file(s) in the webroot.
- Abnormal authentication success immediately prior to file upload in some cases — credential reuse suspected.
- Final defacement observed with index page replaced; persistence artifacts (webshells) detected.

Indicators of Compromise (IOCs)
- See iocs/iocs.csv for a machine-readable list. The report includes a human-readable IOCs section.

Example Splunk searches
- See /searches for ready-to-run SPL files.

Detection & mitigation recommendations
- Harden upload endpoints (validate filetype server-side, deny execution in upload directories).
- Enforce MFA, rate-limiting and lockouts for login endpoints.
- Block malicious IPs at the perimeter and monitor for reattempts.
- Re-image or restore from a known-good backup if persistence is suspected. Conduct a full host forensics review.
- Implement file integrity monitoring for webroot and watch for newly created executable files.

Playbook / Runbook
See playbooks/containment.md for the short, actionable runbook covering containment, eradication, recovery and lessons learned.

Contributing
Open issues and pull requests are welcome. Avoid adding real PII or customer telemetry.

License
This repository is licensed under the MIT License. See LICENSE for details.

Contact
Investigation assembled by: MK-ultra98-creator
