# aicores-python-security-sdk
Security SDK for python
Following tools: 
- pip-audit - pip-audit is a tool for scanning Python environments for packages with known vulnerabilities. It uses the Python Packaging Advisory Database (https://github.com/pypa/advisory-database) via the PyPI JSON API as a source of vulnerability reports. [link](https://pypi.org/project/pip-audit/)
- safety - Safety CLI is a Python dependency vulnerability scanner designed to enhance software supply chain security by detecting packages with known vulnerabilities and malicious packages in local development environments, CI/CD, and production systems. Safety CLI can be deployed in minutes and provides clear, actionable recommendations for remediation of detected vulnerabilities. [link](https://pypi.org/project/safety/)
- bandit - Bandit is a tool designed to find common security issues in Python code. To do this, Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files, it generates a report. [link](https://bandit.readthedocs.io/en/latest/index.html)

## How to install
### Create a virtual environment
```bash
python -m venv venv
```

### Activate the virtual environment
```bash
source venv/bin/activate
```

###
```bash
pip install bandit pip-audit safety
pip install flask==0.5
```
###
in Terminal type:
```bash
python Security-sdk.py
```

## example of full security sweep:
```bash
pip-audit (or pip-audit --desc)
safety system-scan
bandit (filename)
```
