# Private Notes — minimal Software Security Assignment I

This repository contains the runnable project: three Python HTTP processes, a
separately installed helper, private notes, roles, four CTF experiments, tests and
Jenkins. Optional supply-chain experiments and GUI are excluded.

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
python -m unittest discover -s tests -v
```

Three test methods contain multiple assertions and eight before/after attack
runs. All should pass. Tests themselves explicitly enable one lab fixture at a
time and turn it off for the fixed run. Do not export LAB_VULN in your shell.

## 4. Run checks

```sh
python -m compileall -q app.py helper scripts tests
python scripts/check_dependencies.py
bandit -q app.py helper/note_exporter -r
pip-audit --disable-pip --no-deps -r requirements-dev.lock
```

Nonzero exit blocks release. B310 is narrowly accepted for fixed loopback HTTP;
B608 is accepted only on the intentionally unsafe SQL fixture line. These
exceptions are limited to the intentional classroom fixtures. The local helper is checked
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

Run a branch build and a PR build; download the archived analysis and test files.
The pipeline fails on build,
metadata, Bandit, audit or test failure and archives results even on failure.

## Run the PoCs

Each PoC starts a fresh vulnerable three-process cluster and prints its response:

```sh
python scripts/poc_validation.py
python scripts/poc_sql.py
python scripts/poc_idor.py
python scripts/poc_confused_deputy.py
```

The project history contains separate commits for the helper, services, tests,
PoCs and CI setup.
