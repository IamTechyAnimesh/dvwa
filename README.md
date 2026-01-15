# Reconnaissance
### *1. Service & Stack Enumeration*
<img src="/img/Screenshot%202026-01-16%20005618.png"></br>
### *2. Script Scan*
<img src="/img/Screenshot%202026-01-16%20005054.png"></br>
---
---
# SQLi 
## Summary
A SQL Injection vulnerability was identified in the application’s user lookup functionality. An attacker can manipulate the id parameter to execute arbitrary SQL queries, resulting in unauthorized access to backend database data.
________________________________________
## Severity
High
________________________________________
## Affected Endpoint
•	Endpoint: `/vulnerabilities/sqli/`</br>
•	Method: `POST`</br>
•	Parameter: `id`</br>
________________________________________
## Description
The application directly incorporates user-supplied input from the id parameter into an SQL query without proper sanitization or use of parameterized queries. This allows an attacker to alter query logic and execute arbitrary SQL statements.
</br>Basic input validation is present but insufficient and can be bypassed using crafted payloads.
________________________________________
## Steps to Reproduce
1.	First Intercept the request:
<img src="/img/poc%201.png"></br>
3.	We will be using the id parameter to inject SQLi ( SQLi payload: 1+OR+1=1+UNION+SELECT+user,+password+FROM+users#) :
<img src="/img/poc4.png"></br>
## Actual Result
Injected SQL statements are executed by the database, allowing unauthorized access to sensitive data.
________________________________________
## Impact
•	Arbitrary SQL query execution</br>
•	Disclosure of sensitive user credentials</br>
•	Potential authentication bypass</br>
•	Full database read access depending on DB user privileges</br>
________________________________________
## Root Cause
•	Dynamic SQL query construction using untrusted input</br>
•	Absence of prepared statements</br>
•	Reliance on weak input filtering instead of proper query parameterization</br>
________________________________________
## Remediation
•	Implement prepared statements with bound parameters</br>
•	Eliminate string concatenation in SQL queries</br>
•	Enforce least-privilege database permissions</br>
•	Use modern password hashing algorithms (bcrypt or Argon2)</br>
________________________________________
## References
•	CWE-89: Improper Neutralization of Special Elements used in an SQL Command</br>
•	OWASP Top 10 – Injection</br>

________________________________________
________________________________________

# Reflected Cross-Site Scripting (XSS)

## Summary
A reflected Cross-Site Scripting (XSS) vulnerability was identified where user-supplied input is reflected in the HTTP response without proper sanitization or output encoding. This allows execution of arbitrary JavaScript in the victim’s browser.

---

## Severity
Medium–High

---

## Affected Component
- Input field accepting user-controlled data
- Request Method: GET / POST
- Execution Context: HTML response body

---

## Description
The application reflects user input directly into the response page without applying appropriate output encoding. By injecting a crafted HTML element containing a JavaScript event handler, an attacker can trigger script execution in the victim’s browser.

---

## Steps to Reproduce

1. Navigate to the vulnerable input field.
<img src="img/Screenshot 2026-01-16 011440.png"></br>
3. Submit the following payload as input:

```html
<img src=x onerror=alert(1)>
```
<img src="img/Screenshot 2026-01-16 011448.png"></br>
<img src="img/Screenshot 2026-01-16 011455.png"></br>
3. Observe the rendered response in the browser.

---
## Expected Result
User input should be sanitized or safely output-encoded, preventing injected scripts from executing.

---
## Actual Result
Injected HTML and JavaScript are executed in the user’s browser.

---
## Impact
- Arbitrary JavaScript execution
- Session hijacking risk
- Credential theft via phishing
- Malicious redirection or page manipulation
- Exploitable via crafted links

---
## Root Cause
- Lack of output encoding
- Improper handling of user-supplied input
- No Content Security Policy (CSP) enforcement

---
## Remediation
- Apply context-aware output encoding (HTML entity encoding)
- Validate and sanitize all user input server-side
- Implement a restrictive Content Security Policy (CSP)
- Avoid reflecting raw user input in responses
