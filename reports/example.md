# Example Threat-Hunting Report

**Date:** 2025-10-09  
**Analyst:** Lauren Roberts  
**Dataset:** `sample_access.log`

| Finding | Description | Evidence | Severity | Recommendation |
|----------|--------------|-----------|-----------|----------------|
| 1 | Brute-force login attempt | 200 GET `/login` – 401 × 37 IPs | High | Add rate-limiting / fail2ban |
| 2 | Directory traversal probe | `../etc/passwd` in URI | Medium | Block via WAF rule |
| 3 | Suspicious UA string | `"sqlmap/1.5"` | High | Investigate source IP activity |
| 4 | Large download from rare IP | 4 GB in < 1 min | Medium | Alert for data exfil pattern |

---

### Summary
- Total Requests: 12 350  
- Unique IPs: 420  
- Flagged Events: 56  
- Reporting Time: 00:06 s  

*This sample output demonstrates the reporting logic from `webloghunter.py`.*

