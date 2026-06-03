# Vulnerability Report

---

**Vulnerability Type:** SQL Injection / Cross-Site Scripting (XSS) / Server-Side Request Forgery (SSRF) / Remote Code Execution (RCE) / Insecure Direct Object Reference (IDOR) / Broken Access Control / Sensitive Data Exposure / Authentication Bypass / Other

**Affected Component:** [Endpoint URL, module, or feature]

**Severity:** Critical / High / Medium / Low

**CVSS Score:** [e.g., 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)]

**Program:** [Program Name]

---

## Description

[Provide a clear, concise description of the vulnerability. Explain the root cause (e.g., insufficient input validation, missing authentication checks, misconfigured CORS policy, etc.). Describe why this is a security issue and the potential risk it poses to the application and its users. Be professional and factual.]

**Root Cause Analysis:**
- [Technical root cause]
- [Affected code path or configuration]

**Attack Vector:**
- [How an attacker could discover and exploit this vulnerability]

---

## Steps to Reproduce

### Prerequisites

- **Account type required:** [None / Regular user / Admin / Specific role]
- **Tools used:** [Burp Suite / curl / browser / custom script]
- **Environment:** [Production / Staging / Public URL]

### Reproduction Steps

1. **Prepare the request**
   ```
   [Request method and URL]
   ```

2. **Send the payload**
   - Headers:
     ```
     [Relevant request headers]
     ```
   - Body:
     ```
     [Request body / payload]
     ```
   - Tool command (if using curl):
     ```bash
     curl -X [METHOD] '[URL]' \
       -H 'Content-Type: [type]' \
       -d '[payload]'
     ```

3. **Observe the response**
   - Status code: [HTTP status code]
   - Response body (relevant excerpt):
     ```
     [Response content demonstrating the issue]
     ```

4. **Verify**
   - [Additional verification steps]
   - [Confirm this is not intended behavior]

---

## Impact

[Clearly describe the business impact and security risk.]

**Possible Impacts:**
- [ ] Data breach / Data exfiltration
- [ ] Unauthorized access to sensitive functionality
- [ ] Privilege escalation
- [ ] Account takeover
- [ ] Denial of service
- [ ] Financial loss
- [ ] Reputation damage
- [ ] Compliance violation (GDPR, PCI-DSS, etc.)

**Detailed Impact Description:**
[Explain what an attacker could realistically achieve by exploiting this vulnerability. Quantify the risk where possible — e.g., number of affected users, volume of accessible data, criticality of exposed functionality.]

---

## Proof of Concept

[Include a minimal, self-contained PoC that demonstrates the vulnerability. This can be a curl command, a Python script, a JavaScript snippet, or any other reproducible method. Do NOT include PoCs that cause actual damage or access production user data unnecessarily.]

```python
#!/usr/bin/env python3
# Minimal PoC - [Vulnerability Type]
import requests

target = "[URL]"
payload = "[payload]"

# Step 1: Request
response = requests.get(f"{target}{payload}")

# Step 2: Validate response
if "[expected_signature]" in response.text:
    print("[+] Vulnerability confirmed!")
    print(f"    Response: {response.text[:200]}")
else:
    print("[-] Vulnerability not confirmed")
```

```bash
# curl PoC
curl -s -X [METHOD] '[URL]' \
  -H 'X-Testing: authorized-security-research' \
  [payload_flag] | grep -i '[evidence_string]'
```

---

## Remediation Suggestion

### Immediate Mitigation

- [Quick fix that can be deployed immediately, e.g., disable the affected feature, tighten WAF rules]

### Long-term Fix

1. **Input Validation**
   - [Specific advice on input sanitization, e.g., parameterize queries, validate against allowlist]

2. **Access Control**
   - [Specific advice on authorization checks, e.g., enforce server-side permission verification]

3. **Configuration Changes**
   - [Specific configuration changes, e.g., disable directory listing, restrict file permissions]

### Recommended Code Change

```diff
- [vulnerable code]
+ [fixed code]
```

### Prevention for Future

- Add automated security testing to CI/CD pipeline
- Conduct regular security training for development team
- Perform threat modeling during design phase
- Implement security linting rules in IDE

---

## Supporting Material

### Screenshots / Screen Recordings

[Attach screenshots or links to screen recordings demonstrating the vulnerability. Ensure sensitive information is redacted.]

### Request/Response Logs

**Request:**
```
[Full HTTP request]
```

**Response:**
```
[Full HTTP response]
```

### Additional Information

- **Bug discovered on:** [Date]
- **Browser/Client version:** [Relevant versions]
- **Other relevant findings:** [Related vulnerabilities, chaining possibilities]

---

## Disclosure & Collaboration

- [ ] I have read and agree to the program's disclosure policy
- [ ] This vulnerability was discovered during authorized testing
- [ ] I have not accessed, downloaded, or modified production user data beyond what was necessary to demonstrate the vulnerability
- [ ] I am available to assist with verification and remediation

---

*This report is submitted as part of a authorized bug bounty program. All testing was conducted in accordance with the program's scope and rules of engagement.*
