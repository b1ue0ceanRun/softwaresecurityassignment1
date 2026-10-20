"""Fail closed on unexpected declared runtime dependencies or helper metadata."""
from importlib.metadata import distribution
from pathlib import Path
import tomllib

assert Path('requirements.txt').read_text().splitlines() == ['./helper']
metadata = tomllib.loads(Path('helper/pyproject.toml').read_text())
assert metadata['project']['name'] == 'note-exporter'
assert metadata['project']['version'] == '1.0.0'
assert metadata['project']['dependencies'] == []
assert metadata['build-system']['requires'] == ['setuptools==83.0.0']
installed = distribution('note-exporter')
assert installed.version == '1.0.0'
assert not installed.requires
print('PASS: only approved local runtime dependency note-exporter==1.0.0')
