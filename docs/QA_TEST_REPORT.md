\# Email Threat Detection Platform

\## QA Testing Report



\## 1. Objective

The objective of testing is to verify that the platform can analyze

`.eml` files, identify suspicious email characteristics, extract

IOCs, calculate threat scores, and display investigation results.



\---



\## 2. Test Dataset



| ID | Email | Type | Expected |

|---|---|---|---|

| T01 | phishing\_microsoft.eml | Malicious | High Risk |

| T02 | bank\_kyc.eml | Malicious | High Risk |

| T03 | password\_reset.eml | Malicious | Medium/High Risk |

| T04 | normal\_notification.eml | Legitimate | Low Risk |

| T05 | newsletter.eml | Legitimate | Low Risk |



\---



\## 3. Functional Testing



| ID | Test | Expected Result | Actual Result | Status |

|---|---|---|---|---|

| T01 | Upload .eml | File analyzed | Pending | Pending |

| T02 | Extract sender | Sender extracted | Pending | Pending |

| T03 | Extract subject | Subject extracted | Pending | Pending |

| T04 | Extract Reply-To | Reply-To extracted | Pending | Pending |

| T05 | Analyze SPF | SPF status detected | Pending | Pending |

| T06 | Analyze DKIM | DKIM status detected | Pending | Pending |

| T07 | Analyze DMARC | DMARC status detected | Pending | Pending |

| T08 | Extract URLs | URLs extracted | Pending | Pending |

| T09 | Extract domains | Domains extracted | Pending | Pending |

| T10 | Calculate score | Threat score generated | Pending | Pending |

| T11 | Classification | Risk classification generated | Pending | Pending |



\---



\## 4. Edge Case Testing



| ID | Test Case | Expected Result | Actual Result | Status |

|---|---|---|---|---|

| E01 | No URL | Application does not crash | Pending | Pending |

| E02 | Multiple URLs | All URLs extracted | Pending | Pending |

| E03 | Missing Reply-To | Analysis continues | Pending | Pending |

| E04 | Missing authentication headers | Handled safely | Pending | Pending |

| E05 | Malformed .eml | Proper error displayed | Pending | Pending |

| E06 | Empty body | Application does not crash | Pending | Pending |



\---



\## 5. Security Signal Testing



| ID | Signal | Expected Result | Actual Result | Status |

|---|---|---|---|---|

| S01 | SPF failure | Risk increases | Pending | Pending |

| S02 | DKIM failure | Risk increases | Pending | Pending |

| S03 | DMARC failure | Risk increases | Pending | Pending |

| S04 | From/Reply-To mismatch | Warning generated | Pending | Pending |

| S05 | Suspicious URL | URL identified | Pending | Pending |

| S06 | Credential request | Suspicious signal detected | Pending | Pending |

| S07 | Urgency language | Suspicious signal detected | Pending | Pending |



\---



\## 6. Final Summary

Total tests: Pending

Passed: Pending

Failed: Pending

Blocked: Pending



\---



\## 7. Conclusion

The QA process verifies email parsing, authentication analysis,

IOC extraction, threat scoring, classification and result presentation.

Final results will be updated after integration testing.

