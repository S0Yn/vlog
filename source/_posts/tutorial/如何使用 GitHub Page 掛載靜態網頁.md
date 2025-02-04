---
title: 使用 GitHub Page 掛載靜態網頁
published: 2024-05-15
tags: [Github Page]
category: 教學
draft: false
password: Github
abstract: 免費的最香了
message: 就跟你講吧 ! 密碼是 Github
---

# 如何使用 GitHub Page 掛載靜態網頁

使用 GitHub Page 可以永久免費的掛載自己的靜態網頁
不用使用任何終端機或是指令也能輕鬆掛載你的部落格
>這篇文章將假設已經擁有一個靜態網站需要掛載

範例:
* [My Blog](https://blog.s0z.me/)

所需工具:
1. [GitHub Desktop](https://central.github.com/deployments/desktop/desktop/latest/win32)
2. 一個編譯好的靜態網站
>靜態網站產生待更新教學


---

### Git Repo創建

首先 我們先登入 GitHub [創建一個 Repository]([repository](https://github.com/new))

![圖片](https://hackmd.io/_uploads/ByYz6n-7A.png)

這邊用 GitHub Desktop 來處理檔案

![圖片](https://hackmd.io/_uploads/H1xCCnW7C.png)

### 檔案處理
這邊會自動開啟 GitHub Desktop 按下 ```Clone```

![圖片](https://hackmd.io/_uploads/By1DkpWXA.png)

>這邊我的網頁目錄在 ```D:\Documents\GitHub\blog_for_test```
請先記下 ```Local path``` 的路徑以便等下的操作

接下來打開檔案總管 進入記下的路徑

![圖片](https://hackmd.io/_uploads/BkwXg6bXC.png)

這是我的靜態網頁的網站 , 如果你還沒有自己的網站 , 可以參考我的另一篇文章

![圖片](https://hackmd.io/_uploads/SyeugpWmR.png)

接下來把網站的資料都丟到裡面

![圖片](https://hackmd.io/_uploads/BJ1nlTW70.png)

打開 GitHub Desktop 可以看到讀取到檔案
在 ```Summary (required)``` 輸入 upload
點擊 ```Commit to main```

![圖片](https://hackmd.io/_uploads/ByjCeaZQA.png)

然後,我們點擊 ```Publish branch```

![圖片](https://hackmd.io/_uploads/rJQBWaW7R.png)

### GitHub 設定

回到剛剛創建的 repo
依序點擊 ```Setting``` -> 下方的 ```Pages```
![圖片](https://hackmd.io/_uploads/r1qBzpbXC.png)

將底下 ```Branch``` 底下的 **None** 改成 **main**

![圖片](https://hackmd.io/_uploads/BJ-JQabXA.png)

然後點擊 ```Save```

![圖片](https://hackmd.io/_uploads/HyxWmTZQA.png)

等過幾分鐘後 , 重新整理一下頁面
上面就會顯示你的網站網址

![圖片](https://hackmd.io/_uploads/H118QTbQ0.png)

### 維護與更新

之後任何檔案刪除或改動都需要在剛剛放置檔案的資料夾做更動

舉個例子 : 假如我今天要增加一個網頁叫做 ```test.html```

![圖片](https://hackmd.io/_uploads/Sy-xETWXR.png)

新增過後 打開 GitHub Desktop
這邊會顯示你增加了```test.html```
點擊底下藍色的 ```Commit to main```

![圖片](https://hackmd.io/_uploads/BJIf4p-XC.png)

再點擊旁邊的 ```Push origin```
等他跑完後 , 等待伺服器處理好大約三分鐘 ,即可完成改動

![圖片](https://hackmd.io/_uploads/By0dNTWQC.png)

---
## Q&A
Q : 為何我的CSS載入不正確?
:::info
1. 假如你的資料夾有_開頭的檔案或是資料夾,請新增一個空白檔案名稱為```.nojekyll```放在你的網站```index.html```目錄

2. 你編譯的過程中可能 ```site``` 或是 ```base``` 沒有設定好
請檢查你的設定是否正確
:::

















