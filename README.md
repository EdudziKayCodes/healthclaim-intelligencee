# HealthClaim Intelligence (HCI) - MVP

Implements the MVP scope of the business plan: secure import, configurable validation, rejection categorisation,
status/payment tracking, dashboard and reconciliation. No installs needed (Python 3.9+ only).

    python3 server.py        # open http://localhost:8000
    Login: admin / admin123  (set HCI_ADMIN_PW before first run to change it)

Try it: Import tab -> "Load synthetic demo data" -> Claims -> "Run validation" -> Dashboard / Reconciliation.

Design notes
- Nothing auto-submits to CLAIM-it or any insurer; flags are explainable and a human decides.
- Rule deadlines (90/180 days) are PLACEHOLDERS - replace with verified insurer rules.
- Roles: admin (everything), officer (import/validate/update claims), viewer (read-only).
- Use synthetic or de-identified data only until you have agreements and Act 843 compliance in place.
- Before real use: put it behind HTTPS (reverse proxy), set Secure cookies, add password change/user management,
  and move SQLite -> PostgreSQL as the plan proposes.
