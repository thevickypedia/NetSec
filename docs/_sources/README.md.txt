# NetSec (Network Security)
NetSec is a tool to analyze devices connecting to the router and alert accordingly when a new device is connected.

This app can display and store intruders' IP address, MAC address, and Block the device.

> Blocking device feature is currently available only for `Netgear` router users.

```python
from netsec import network_monitor, SupportedModules

if __name__ == '__main__':
    network_monitor(module=SupportedModules.att, init=True)  # Create snapshot
    network_monitor(module=SupportedModules.att, init=False)  # Run the scan
```

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

## [Release Notes](https://github.com/thevickypedia/NetSec/blob/master/release_notes.rst)
**Requirement**
```shell
python -m pip install changelog-generator
```

**Usage**
```shell
changelog reverse -f release_notes.rst -t 'Release Notes'
```

## Linting
`PreCommit` will ensure linting, and the doc creation are run on every commit.

**Requirement**
```shell
pip install sphinx==5.1.1 pre-commit recommonmark
```

**Usage**
```shell
pre-commit run --all-files
```

## Runbook
[![made-with-sphinx-doc](https://img.shields.io/badge/Code%20Docs-Sphinx-1f425f.svg)](https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html)

[https://thevickypedia.github.io/NetSec/](https://thevickypedia.github.io/NetSec/)
