# Containment & Remediation Playbook (short)

1) Immediate containment
- Block attacker IPs on perimeter firewalls and WAF.
- Disable the vulnerable upload endpoint or take the host offline.
- Change/rotate credentials for accounts that may be compromised.

2) Triage & evidence collection
- Collect IIS logs, web application logs, and IDS alerts to secure storage.
- Dump running processes and network connections from the host.
- Preserve copies of suspicious files (webshells) for analysis.

3) Eradication
- Remove webshell files and any modifications discovered in webroot.
- Check cron/scheduled tasks for persistence and remove unauthorized entries.
- Patch the application code and update server-side validation.

4) Recovery
- Restore from a known-good backup or re-image the server if persistence cannot be ruled out.
- Re-enable services only after verifying integrity and applying hardening changes.

5) Post-incident actions
- Conduct a root cause analysis and update detections in Splunk.
- Update incident reports and notify stakeholders as required.
