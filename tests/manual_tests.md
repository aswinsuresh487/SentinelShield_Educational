# SentinelShield Manual Testing Documentation

**Project**: SentinelShield Educational WAF
**Environment**: Kali Linux (VirtualBox)
**Author**: [Your Name]
**Date**: [Today's Date]

---

## Test 1: Normal Request - Homepage

**Command:**
```bash
curl "http://localhost:5000/index.php"
```

**Expected Result:** ALLOWED (request should pass through)

**Actual Result:** 
[Fill in after testing - Did it work? What was the response?]

**Analysis:** 
[Why should this be allowed? What makes it "clean"?]

---

## Test 2: SQL Injection - OR Clause

**Command:**
```bash
curl "http://localhost:5000/user.php?id=1' OR '1'='1"
```

**Expected Result:** BLOCKED (403 Forbidden)

**Actual Result:** 
[Fill in after testing]

**Attack Type:** SQL Injection

**Why Detected:** 
[Explain which pattern matched and why]

**Real-world Impact:** 
[What could an attacker do with this?]

**Detection Rule:** 
[Which regex pattern caught this?]

---

## Test 3: XSS - Script Tag Injection

**Command:**
```bash
curl "http://localhost:5000/search.php?q=<script>alert('XSS')</script>"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 4: Path Traversal - /etc/passwd

**Command:**
```bash
curl "http://localhost:5000/file.php?page=../../../../etc/passwd"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 5: Command Injection - Semicolon

**Command:**
```bash
curl "http://localhost:5000/ping.php?host=127.0.0.1; cat /etc/passwd"
```

**Expected Result:** BLOCKED

**Actual Result:** [Fill in]

**Analysis:** [Your explanation]

---

## Test 6: [Add Your Own Test]

**Command:**
```bash
[Your curl command]
```

**Expected Result:** [BLOCKED or ALLOWED]

**Actual Result:** [Your observation]

**Analysis:** [Your explanation]

---

## Summary

**Total Tests Performed:** [Number]
**Blocked Correctly:** [Number]
**Allowed Correctly:** [Number]
**False Positives:** [Number - legitimate requests blocked]
**False Negatives:** [Number - attacks that got through]

**Key Findings:**
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

**Improvements Needed:**
1. [Improvement 1]
2. [Improvement 2]
3. [Improvement 3]
