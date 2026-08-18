# Splunk Lab 1 — Web Application Defacement (Converted Report)

Authors: MK-ultra98-creator
Date: 2026-08-18

Executive summary
-----------------
This report documents a Splunk-driven investigation into a web application defacement affecting a site referenced as `startrek.com` (placeholder). Using IIS access logs, HTTP application logs, and network IDS alerts, the incident was reconstructed from initial reconnaissance through successful file upload and public defacement. The attacker used an upload endpoint and likely a webshell to place content in the webroot, replacing the site's index with a defacement page. Credential abuse and incomplete server-side validation were contributing factors.

Scope & audience
----------------
Scope: public-facing web application defacement analysis focusing on detection, forensic reconstruction, and remediation guidance.
Audience: SOC analysts, incident responders, students learning Splunk-based investigations.

Data sources
------------
- IIS access and error logs (access logs showing GET/POST patterns)
- Web application logs (HTTP POST content and responses)
- Network IDS alerts (signature and anomaly-based alerts)
- Authentication logs (login success/failure events)
- Files recovered from the webroot and uploaded artifacts

Methodology
-----------
We followed the Lockheed Martin Cyber Kill Chain and enriched it with Splunk analysis.

1. Reconnaissance & scanning
   - Detect high-volume or systematic requests to common paths (robots.txt, admin panels, upload endpoints).
   - Look for unusual user agents or scripted clients (curl, python-requests).

2. Target identification & vulnerability probing
   - Identify repeated probing of upload endpoints and endpoints that accept multipart/form-data.
   - Detect requests attempting path traversal or file-type bypass techniques.

3. Credential attacks
   - Search for bursts of authentication failures followed by a successful login from the same client IP or adjacent IPs.
   - Correlate with known bruteforce indicators (many users, many failed attempts from same IP).

4. Exploitation — Malicious file upload
   - Identify POST requests with suspicious content types and filenames ending in executable extensions (.php, .jsp, .asp).
   - Correlate with subsequent 200/201 responses and file presence in webroot.

5. Post-exploitation — Persistence and defacement
   - Look for web requests invoking uploaded webshells (parameters like `cmd=` or `shell=` or evidence of base64 decoding in query strings).
   - Detect modifications to index files and new files with web-executable extensions in webroot.

Findings and timeline (edited summary)
--------------------------------------
The original lab document included a full timeline built from log timestamps. Below is an edited, improved summary highlighting key events:

- T0 — Reconnaissance: Multiple HTTP probes detected from external IP(s) scanning for upload endpoints and admin panels. Requests included unusual user agents and automated patterns.

- T1 — Credential abuse: A spike of authentication failures against the login endpoint from one or more IP addresses, followed by a successful authentication from one of those addresses.

- T2 — Exploitation: A multipart/form-data POST to an upload endpoint with a file named `cmd.php` (or similar) was accepted. Response codes indicate the server saved the file.

- T3 — Post-exploitation: HTTP requests referencing the uploaded file execute commands or provide interactive behavior indicative of a webshell (e.g., parameters that contain `system(`, `exec(`, `base64_decode(`, or `eval`).

- T4 — Defacement: The site’s index page was replaced with defacement content. Additional artifacts show files placed into the webroot and/or scheduled tasks modified.

Impact
------
- Public defacement of a public-facing site (reputation, customer trust).
- Potential for further data exfiltration or persistent backdoors if webshells remained on the host.

Indicators of Compromise (IOCs)
-------------------------------
Note: The original binary document contained IOCs in-line. All data in this repo is intentionally left intact (no redaction). The iocs/iocs.csv contains the structured list. Example IOC fields:
- ip,first_seen,last_seen,protocol,uri,user_agent,filename,sha256,comments
- 203.0.113.45,2026-07-01T12:34:00Z,2026-07-01T12:50:00Z,HTTP,/upload.php,"curl/7.68.0","cmd.php",<sha256>,"Upload of webshell"

Searches and dashboards (reproducible)
--------------------------------------
Add these saved searches to Splunk and point them at the appropriate indexes.

1) Detect suspicious uploads and executable file writes (upload_detection.spl)
```spl
index=iis sourcetype="iis:access" method=POST
| where like(uri_path, "%upload%") OR like(uri_path, "%file_upload%")
| rex field=uri_path "(?<upload_path>/.*)"
| table _time clientip uri_path useragent status uri_query
| where match(uri_query, "(?i)\.php|\.jsp|\.asp|eval\(|base64_decode\(|system\(")
```

2) Detect creation / access of files with executable extensions in webroot
```spl
index=http sourcetype="http:access" (method=PUT OR method=POST)
| where like(uri_path, "%.php") OR like(uri_path, "%.jsp")
| stats count by clientip uri_path useragent status
```

3) Credential stuffing / brute force detection (suspicious_auth.spl)
```spl
index=auth sourcetype="auth:log" action=failure
| stats count by user clientip
| where count > 20
```

4) Webshell behavior indicators
```spl
index=iis sourcetype="iis:access"
| search uri_query="*eval*" OR uri_query="*base64_decode*" OR uri_query="*system(*" OR uri_query="*exec(*"
| table _time clientip uri_path uri_query useragent
```

Recommended detection and mitigation
------------------------------------
- Harden upload endpoints: server-side validation, content scanning, and store uploads outside the webroot. Deny execution permissions in upload directories.
- Use WAF rules that block suspicious multipart payloads and block known webshell signatures.
- Implement MFA, rate limiting, and account lockouts to reduce credential abuse risks.
- Monitor for new files in webroot and maintain file integrity monitoring.
- Block and monitor offending IPs; correlate across environments for distributed campaigns.

Playbook (short)
-----------------
1. Contain: block offending IPs, isolate the host from network, disable the vulnerable upload functionality.
2. Investigate: collect volatile memory, list running processes, identify webshells and scheduled tasks.
3. Eradicate: remove webshells, restore files from a known-good backup, apply patches.
4. Recover: re-image hosts if persistence cannot be ruled out; restore services and validate integrity.
5. Lessons learned: implement detection coverage and escalate to change control for upload code remediation.

Appendix: full original text (omitted)
-------------------------------------
The full original binary document text is long and was converted and condensed into this report. If you need a verbatim transcription of the entire .docx content, request it and we will provide it as an appendix; for maintainability this repository stores a cleaned, human-focused report instead.

