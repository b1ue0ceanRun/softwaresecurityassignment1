# Private Notes — minimal Software Security Assignment I

Only required scope: three Python HTTP processes, a separately installed benign
helper, private notes, roles, four CTF vulnerability experiments, tests, Jenkins and
report. No optional supply-chain experiments, GUI or public hosting.

## 1. Build

Run from this directory with Python 3.11 or newer:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-build-isolation -r requirements.txt
python scripts/check_dependencies.py
```

`requirements-dev.lock` pins the analysis/build environment. The only application
runtime dependency is the local `note-exporter` package. Pip builds and installs
it as a wheel; it is not copied into app.py. Internet is needed for tooling setup
and security advisory checks. No database server or Docker is needed.

## 2. Seed and run the smallest demonstration

```sh
python scripts/run_demo.py
```

This starts three separate processes on temporary loopback ports, seeds users
and two notes automatically, prints create/read/export/denial/admin results, then
stops the processes. Expected: own operations 200, Bob's note and Alice's admin
request 403, administrator count 200. Each run starts with fresh in-memory data.

## 3. Run the tests

```sh
mkdir -p evidence
python -m unittest discover -s tests -v > evidence/tests.txt 2>&1
cat evidence/tests.txt
cat evidence/vulnerabilities.json
```

Three test methods contain multiple assertions and eight before/after attack
runs. All should pass. Tests themselves explicitly enable one lab fixture at a
time and turn it off for the fixed run. Do not export LAB_VULN in your shell.

## 4. Run checks

```sh
python -m compileall -q app.py helper scripts tests
python scripts/check_dependencies.py > evidence/dependencies.txt
bandit -q app.py helper/note_exporter -r -f json -o evidence/bandit.json
pip-audit --disable-pip --no-deps -r requirements-dev.lock -f json -o evidence/pip-audit.json
```

Nonzero exit blocks release. B310 is narrowly accepted for fixed loopback HTTP;
B608 is accepted only on the intentionally unsafe SQL fixture line. These
exceptions are explained in REPORT.md. The local helper is reviewed and checked
by metadata policy; there is no public advisory entry for this private package.

## 5. Keep services running for manual requests

Use four terminal tabs, activate `.venv` in each and work in this directory.
In the first tab generate a secret and copy the printed value to the next two:

```sh
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Tab 1:
```sh
export API_RESOURCE_KEY='paste-the-generated-value'
python app.py resource --port 8102
```
Tab 2, using the same value:
```sh
export API_RESOURCE_KEY='paste-the-generated-value'
python app.py api --port 8101
```
Tab 3 (no service secret needed):
```sh
unset API_RESOURCE_KEY
python app.py processor --port 8103
```
Tab 4:
```sh
curl -s http://127.0.0.1:8101/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'
```
Copy the returned token:
```sh
export TOKEN='paste-the-returned-token'
curl -s http://127.0.0.1:8101/read -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"id":1}'
curl -s http://127.0.0.1:8101/export -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{"id":1}'
```

Seed accounts: `alice/alice-pass`, `bob/bob-pass`, `admin/admin-pass`. Admin can
count notes, but cannot read other users' notes. Stop each server with Ctrl+C.

## 6. Jenkins — required external setup

Commit/push this repository to your Git host. On a Jenkins server with Python
3.11+, Git and Pipeline/SCM branch-source plugins, create a **Multibranch Pipeline**,
point it to this repository, enable branch and pull-request discovery, select
`Jenkinsfile`, and configure your Git host's push/PR webhook. A five-minute SCM
poll is a fallback. Jenkinsfile alone cannot create server jobs or webhooks.

Run a branch build and a PR build; download archived `evidence/*` and record the
actual build URLs before submission. This workspace has local check evidence;
a live Jenkins run has not been performed here. The pipeline fails on build,
metadata, Bandit, audit or test failure and archives results even on failure.

## Files to read / submit

- PLAN.md: initial four-phase plan; Git preserves its pre-implementation commit.
- DESIGN.md: requirements, architecture, data flow, access matrix and STRIDE.
- REPORT.md: English report (approximately 2,269 words).
- AI_USE.md: transparent declaration; review before submission.
- evidence/: saved test and analysis results.
- Jenkinsfile, source, helper, tests and complete `.git` history.

For learning, follow GUIDE_ZH.md one step at a time. No remote push was performed.
