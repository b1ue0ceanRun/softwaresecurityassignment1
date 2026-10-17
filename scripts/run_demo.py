"""Start all three services, print a small demonstration, then clean up."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_system import Cluster

with Cluster() as cluster:
    alice = cluster.login('alice')
    for path, body in [('/create', {'text': 'My first note'}), ('/read', {'id': 1}),
                       ('/export', {'id': 1}), ('/read', {'id': 2}), ('/stats', {})]:
        print(path, cluster.call(path, body, alice))
    print('/stats (admin)', cluster.call('/stats', {}, cluster.login('admin')))
