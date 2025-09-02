<h4 align="center">一款用于检测易受 ForceChangePassword 攻击的账户的工具。</h4>

<p align="center">
  <a href="#installation-instructions">安装说明</a> •
  <a href="#usage">使用方法</a> •
  <a href="#running-pwsentry">运行 pwsentry</a>
</p>

---

PwSentry 通过扫描账户的 `allowedAttributesEffective` 属性中的 `pwdLastSet` 标志，来识别何时可以强制重置已受损 AD 用户（Active Directory 用户）的密码。对一个目标对象拥有 **GenericAll**、**AllExtendedRights** 或 **User-Force-Change-Password** 权限的控制者，可以更改该用户的密码并接管其账户。

# 安装说明 (Installation Instructions)
```sh
git clone github.com/LucasKatashi/pwsentry
cd pwsentry
chmod +x pwsentry.py
```

# 使用方法 (Usage)
```sh
./pwsentry.py -h
```

这将显示该工具的帮助信息。以下是它支持的所有选项。

```

 _____       _____         _
|  _  |_ _ _|   __|___ ___| |_ ___ _ _
|   __| | | |__   | -_|   |  _|  _| | |
|__|  |_____|_____|___|_|_|_| |_| |_  |
                                  |___|
                        by: katashi 🇨🇳
用法: pwsentry.py [-h] [-w WORDLIST] [-t TARGET_USER] -i IP -u USER -d DOMAIN
                   -p PASSWORD

ForceChangePassword 检查器。

选项:
  -h, --help            显示此帮助信息并退出
  -w, --wordlist WORDLIST
                        包含用户名的单词列表路径（每行一个用户名）
  -t, --target_user TARGET_USER
                        单个目标用户名
  -i, --ip IP           单个 IP 地址或包含 IP 地址的文件路径（每行一个 IP）
  -u, --user USER       用于身份验证的用户名
  -d, --domain DOMAIN   用于身份验证的完整域名 (FQDN)
  -p, --password PASSWORD
                        用于身份验证的密码
```