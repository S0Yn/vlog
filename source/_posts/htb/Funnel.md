---
title: HTB - Funnel
published: 2024-05-14
tags: [HTB]
category: Write Up
draft: false
password: startpoint
abstract: 隧道的另一頭是什麼呢?
message: 就跟你講吧 ! 密碼是 startpoint
---

# HTB - Funnel
![image](https://hackmd.io/_uploads/rkVBCG_JA.png)

* PostgreSQL 指令
* SSH tunnel 創建
* FTP anonymose Login
* hydra 暴力破解



---
:::info
Target host  : **10.129.288.195**
nmap argment : **nmap -sC -sV -Pn -T4 10.129.288.195**
:::

![image](https://hackmd.io/_uploads/HyiRs-uyC.png)

觀察掃描結果可以發現 ftp-anon : Anonymous login allowed

代表說可以匿名登入該主機的ftp server

---

這邊用 get 把目錄中的文件都下載到本地
如下圖 :
![image](https://hackmd.io/_uploads/H1sk6bukR.png)

---

打開下載回來兩個檔案，提供了兩個重要的資訊

1. password_policy.pdf 提到新進員工的預設密碼為 funnel123#!#
2. welcome_28112022 群發電子郵件列出了所有新進員工的 email

![image](https://hackmd.io/_uploads/SkAf1Gu1A.png)

---
將所有新進員工的帳號記錄下來，透過 hydra 來進行 ssh 密碼爆破
![image](https://hackmd.io/_uploads/SkkxKfuyA.png)

---

連進去後使用 ss -tls 查看只連接到內網的服務
**127.0.0.1:postgresql**
**127.0.0.1:5432**
![image](https://hackmd.io/_uploads/Hy6wFf_JR.png)


---

但是這個用戶端裡面似乎沒有安裝 psql 客戶端
我們必須創建一個 SSH tunnel 來使用 localhost 的 client 連上去

**ssh -L 5555:localhost:5432 christine@10.129.106.134**
:::success
-L 創建通道
5555:localhost:5432 可以很圖像化的記憶 
[5555]--[localhost]--[5432] <--- 就像一個通道
:::
![image](https://hackmd.io/_uploads/SJw2ofOkC.png)

**psql -U christine -h localhost -p 5555**
:::success
-U 使用者
-h 伺服器位置 (這裡因為要通過 SSH tunnel 連到資料庫所以打 localhost)
-p Port
:::

![image](https://hackmd.io/_uploads/B1hz2z_yR.png)
:::success
\l = 列出伺服器
\c = 連結到伺服器
\dt = 列出資料庫
:::
![image](https://hackmd.io/_uploads/rJyC3fdkA.png)

SELECT * FROM flag; 就可以得到 flag 了







