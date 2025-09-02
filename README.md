<h4 align="center">A tool for detecting accounts vulnerable to ForceChangePassword.</h4>

<p align="center">
  <a href="#installation-instructions">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-pwsentry">Running PwSentry</a>
</p>

---

PWSentry scans an account's `allowedAttributesEffective` for the `pwdLastSet` flag to identify when a compromised AD user can force password resets. Controlling an object with **GenericAll**, **AllExtendedRights**, or **User-Force-Change-Password** over a target lets you change that user's password and take over their account.

# Installation Instructions
```sh
git clone github.com/LucasKatashi/pwsentry
cd pwsentry
chmod +x pwsentry.py
```

# Usage
```sh
./pwsentry.py -h
```

This will display help for the tool. Here are all the switches it supports.
```sh
 _____       _____         _
|  _  |_ _ _|   __|___ ___| |_ ___ _ _
|   __| | | |__   | -_|   |  _|  _| | |
|__|  |_____|_____|___|_|_|_| |_| |_  |
                                  |___|
                        by: katashi 🤠
usage: pwsentry.py [-h] [-w WORDLIST] [-t TARGET_USER] -i IP -u USER -d DOMAIN
                   -p PASSWORD

ForceChangePassword checker.

options:
  -h, --help            show this help message and exit
  -w, --wordlist WORDLIST
  -t, --target_user TARGET_USER
  -i, --ip IP
  -u, --user USER
  -d, --domain DOMAIN
  -p, --password PASSWORD
```