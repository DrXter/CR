# gwreview: Guidewire configuration and source review workbench

One web app for an authorised InsuranceSuite review. Enter the target URL and your Guidewire approval reference, sign in through
Okta in a live remote-browser tab, then run the configuration review and a source review of your uploaded code.

## Run

    docker compose up --build        # or: pip install -r requirements.txt && playwright install chromium && python -m app

Open http://127.0.0.1:8080 (behind TLS in any shared deployment, with `GWR_COOKIE_SECURE=1`). Sign in as `admin`.
The first-start password is printed in the log unless you set `GWR_ADMIN_PASSWORD`.

## RHEL 8/9 one-command install

    sudo bash deploy/rhel/install.sh            # nginx + TLS on 443, systemd service, SELinux, firewalld
    sudo bash deploy/rhel/install.sh --no-nginx # loopback only; use an SSH tunnel

Installs Python 3.11, the Chromium libraries, a `gwreview` service user, `/etc/gwreview/gwreview.env` (admin password inside), and starts `gwreview.service`. Logs: `journalctl -u gwreview -f`. The script was written to the RHEL documentation but not run on a RHEL host here.

## Quick Audit (default screen)
Enter the URL and approval reference, press *Sign in* (a new browser tab opens the application's login: password or Okta plus MFA; it is captured automatically and the audit starts), upload source if needed, read the results.

## Workflow
1. **Engagement**: target URL, Guidewire approval reference, approved window, request rate and budget, Rules-of-Engagement attestation.
   Nothing live runs without these; every request is checked against them.
2. **Authentication**: opens the target in a server-side Chromium shown in the page. Complete Okta (password, push, authenticator code, SMS)
   in the view. When the browser is back on the application, press *Capture session*. The session is encrypted at rest.
   Capture one session per persona (underwriter, claims adjuster, admin...).
3. **Config Review**: anonymous checks (TLS, headers, banners, error pages, methods, CORS, exposed Guidewire tool paths), then an
   authenticated bounded crawl with passive checks, cookie and token-storage checks, an access matrix you define, and an optional logout replay.
   Upload config exports (config.xml, server.xml, web.xml...) for the file-based checks.
4. **Source Review**: upload a zip/tar of the customer layer. Built-in rules (Java, Gosu, PCF, XML, properties, Gradle/Maven/npm), secret and
   entropy detection, dependency and known-vulnerable-library checks, a CycloneDX SBOM. gitleaks, semgrep and osv-scanner are run and
   ingested when installed on the server.
5. **Findings**: triage each item (Confirmed, False positive, Accepted risk, Needs retest). Automation gathers evidence, you decide.
6. **Reports and Audit**: Excel and HTML reports, SBOM, write observations into your review tracker, full audit trail and request log,
   **Destroy** (Guidewire requires results and artefacts, except the report, to be destroyed after the test).

## Guardrails built in
Approval reference and window required; host allow-list (target plus Okta and IdPs reached by redirect from the target only); redirect
hops are checked one by one; minimum 0.5 s between requests; budget capped at 2000; read-only GET navigation; no brute force, fuzzing,
injection or load; kill switch; roles (viewer, reviewer, admin); CSRF header on every state change; strict CSP; login throttle;
SSRF checks on the target; safe archive extraction (zip-slip, symlinks, size limits); secrets are masked in findings.

## Limits you should know
* **Tested only against local mocks** (a mock target and a mock Okta-style IdP with an MFA step), not Guidewire Cloud or a real Okta tenant.
  Run `python -m pytest tests -q` for the 12 end-to-end tests. Real Okta pages (Okta Verify, device trust, bot detection) may behave differently.
* **Forgot the admin password:** `python -m app reset-admin` (stop the server first).
* **Sign-in methods:** password directly on the application and Okta (including custom Okta domains, which are approved when the target redirects to them) both work in the Authentication tab. Okta widget assets (oktacdn.com) and CAPTCHA hosts are allowed as sub-resources only; add others with `GWR_IDP_ASSET_HOSTS`.
* **FIDO2/WebAuthn hardware keys cannot pass through the remote view.** Run the server on your own machine with `GWR_HEADED=1` for those.
* Some IdPs block automated or remote browsers. If sign-in fails, capture from a headed local run.
* About half of the review controls are judgment calls and stay manual. Gosu and PCF analysis is pattern-based, not a compiler-grade parse.
* Rule names and paths vary by Guidewire release; check results against your Application Guide.
* The Docker build and the optional external scanners were not run in the build environment.
* The Guidewire Cloud Console is a shared service: do not point the tool at it for anything but read-only checks the plan allows.
* This is a strong v1 foundation, not a certified product. It needs your approval reference and window before any live use.

## Roadmap
OIDC/SAML single sign-on for the tool itself, PostgreSQL, a worker queue for parallel scans, signed report packages, per-engagement retention policy.
