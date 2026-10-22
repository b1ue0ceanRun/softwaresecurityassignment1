"""CWE-20 PoC: an oversized note is accepted by the vulnerable version."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_system import Cluster

with Cluster('validation') as cluster:
    token = cluster.login('alice')
    status, result = cluster.call('/create', {'text': 'A' * 2001}, token)
    print(status, result.get('flag'))
