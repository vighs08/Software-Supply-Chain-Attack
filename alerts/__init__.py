"""
SSCA-Defender alerting and response.

Part of the project guide's Component 6 (Incident Response and
Orchestration): "Alerting and notification system (... email ...)" and
"Mitigation recommendation engine".

  recommendations.py - recommended actions for each kind of finding
  email_notifier.py  - builds and sends alert emails (SMTP)
  alert_service.py   - turns detection results into alerts, avoids
                       duplicates, records everything in the database
  triage.py          - alert status workflow (New -> Under Review ->
                       Resolved / False Positive)
"""
