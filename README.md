# NetScan
Network Scanner to analyze devices connecting to the router and alert accordingly.

This app can display intruders' IP addresses, MAC addresses, and lets the user Ping the device, and even Block the device.

Block IP Address feature helps the user to remove the specified connections and block the specific IP address.

> Blocking device feature is currently available only for `Netgear` router users.

## Coding Standards
Docstring format: [`Google`](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) <br>
Styling conventions: [`PEP 8`](https://www.python.org/dev/peps/pep-0008/) <br>
Clean code with pre-commit hooks: [`flake8`](https://flake8.pycqa.org/en/latest/) and 
[`isort`](https://pycqa.github.io/isort/)

## [Release Notes](https://github.com/thevickypedia/netscan/blob/master/release_notes.rst)
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

[https://thevickypedia.github.io/netscan/](https://thevickypedia.github.io/netscan/)
