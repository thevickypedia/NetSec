**Platform Supported**

![Generic badge](https://img.shields.io/badge/Platform-Linux|MacOS|Windows-1f425f.svg)

![Python](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)

**Deployments**

[![pypi](https://github.com/thevickypedia/NetSec/actions/workflows/python-publish.yml/badge.svg)](https://github.com/thevickypedia/NetSec/actions/workflows/python-publish.yml)
[![pages-build-deployment](https://github.com/thevickypedia/NetSec/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/thevickypedia/NetSec/actions/workflows/pages/pages-build-deployment)

[![Pypi-format](https://img.shields.io/pypi/format/NetSec)](https://pypi.org/project/NetSec/#files)
[![Pypi-status](https://img.shields.io/pypi/status/NetSec)](https://pypi.org/project/NetSec)

# NetSec (Network Security)
NetSec is a tool to analyze devices connecting to the router and alert accordingly when a new device is connected.

This app can display and store intruders' IP address, MAC address, and Block the device.

> Blocking device feature is currently available only for `Netgear` router users.

## Kick off

**Install**
```shell
python3 -m pip install NetSec
```

**Initiate**
```python
from netsec import network_monitor, SupportedModules

if __name__ == '__main__':
    # SupportedModules.att  # for AT&T users
    # SupportedModules.netgear  # for any network using Netgear router
    network_monitor(module=SupportedModules.att, init=True)  # Create snapshot
    network_monitor(module=SupportedModules.att, init=False)  # Scan for threats and alert
```

> Notifications will not repeat within an hour.

## ENV Variables
Environment variables are loaded from a `.env` file.

- **ROUTER_PASS** - Router password. _Only for `Netgear` users._
- **GMAIL_USER** - Gmail account username to send and email.
- **GMAIL_PASS** - Gmail account password to send and email.
- **RECIPIENT** - Email address to which `NetSec` alerts should be sent.
- **PHONE** - To send an SMS notification - Example: `1234567890`

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

## Pypi Package
[![pypi-module](https://img.shields.io/badge/Software%20Repository-pypi-1f425f.svg)](https://packaging.python.org/tutorials/packaging-projects/)

[https://pypi.org/project/NetSec/](https://pypi.org/project/NetSec/)

## Runbook
[![made-with-sphinx-doc](https://img.shields.io/badge/Code%20Docs-Sphinx-1f425f.svg)](https://www.sphinx-doc.org/en/master/man/sphinx-autogen.html)

[https://thevickypedia.github.io/NetSec/](https://thevickypedia.github.io/NetSec/)
