pipeline {
    agent any
    options { timestamps(); disableConcurrentBuilds() }
    // Configure as Multibranch Pipeline with branch/PR discovery and SCM webhooks.
    triggers { pollSCM('H/5 * * * *') }
    stages {
        stage('Build') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/python -m pip install -r requirements-dev.lock
                    .venv/bin/python -m pip install --no-build-isolation -r requirements.txt
                    mkdir -p evidence
                    .venv/bin/python -m compileall -q app.py helper scripts tests
                    .venv/bin/python scripts/check_dependencies.py > evidence/dependencies.txt
                    .venv/bin/python -m pip freeze > evidence/environment.txt
                '''
            }
        }
        stage('Static and dependency analysis') {
            steps {
                sh '.venv/bin/bandit -q app.py helper/note_exporter -r -f json -o evidence/bandit.json'
                sh '.venv/bin/pip-audit --disable-pip --no-deps -r requirements-dev.lock -f json -o evidence/pip-audit.json'
            }
        }
        stage('Fresh integration environment') {
            steps {
                sh '.venv/bin/python -m unittest discover -s tests -v > evidence/tests.txt 2>&1'
            }
        }
    }
    post {
        always { archiveArtifacts artifacts: 'evidence/*', allowEmptyArchive: true }
    }
}
