"""
Golden Benchmark Dataset for ClarityTI CTI Platform.

Contains curated, rigorously verified positive and negative test cases to measure:
- Website vs Teams Alert separation precision and recall
- False positive rate (FPR) and false negative rate (FNR)
- Evidence score calculation accuracy
- Anti-hallucination validation (record counts, threat actors, CVEs)
- Claim status lifecycle integrity (claimed vs confirmed vs denied)
"""

GOLDEN_BENCHMARK_CASES = [
    # ── POSITIVE INCIDENTS (Eligible for Team Alerts upon passing evidence threshold) ──
    {
        "id": "POS_001_CORP_BREACH",
        "title": "HealthFirst Insurance SEC 8-K filing confirms unauthorized access to database; 2,500,000 customer records stolen",
        "summary": "HealthFirst Insurance filed an 8-K with the SEC confirming a major cyber incident where attackers exfiltrated personal and medical records belonging to 2.5 million customers.",
        "content_clean": "HealthFirst Insurance disclosed today that threat actors compromised its internal corporate network. The unauthorized access was detected last week. An investigation with forensic experts confirmed that 2,500,000 customer records were exfiltrated. The company confirmed the breach to regulators.",
        "source_name": "Reuters Cyber",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Data Breach",
            "claim_status": "confirmed",
            "target_company": "HealthFirst Insurance",
            "min_evidence_score": 50,
            "claimed_records_count": 2500000,
            "cves": []
        }
    },
    {
        "id": "POS_002_INFRA_RANSOMWARE",
        "title": "Colonial Energy systems encrypted by DarkSide ransomware group, forcing shutdown of pipeline operations",
        "summary": "Colonial Energy suffered a devastating ransomware attack by DarkSide that encrypted operational control systems and forced an emergency shutdown of the major fuel pipeline.",
        "content_clean": "Colonial Energy confirmed its pipeline network was shut down following a ransomware attack. DarkSide threat actors deployed ransomware across corporate servers and demanded $5 million. Critical infrastructure operations were disrupted nationwide.",
        "source_name": "BleepingComputer",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Ransomware",
            "claim_status": "confirmed",
            "target_company": "Colonial Energy",
            "threat_actor": "DarkSide",
            "min_evidence_score": 50,
        }
    },
    {
        "id": "POS_003_BANK_EXTORTION",
        "title": "RansomHub lists Metro Bank on dark web leak site with 500GB proof samples of customer database",
        "summary": "RansomHub ransomware group has listed Metro Bank on their extortion leak site, publishing proof samples containing confidential financial data after ransom negotiations broke down.",
        "content_clean": "RansomHub added Metro Bank to its dark web leak portal today. The threat actor claims to have exfiltrated sensitive databases and published employee credentials and customer account data as proof.",
        "source_name": "Dark Reading",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Ransomware",
            "claim_status": "claimed",
            "target_company": "Metro Bank",
            "threat_actor": "RansomHub",
            "min_evidence_score": 50,
        }
    },
    {
        "id": "POS_004_CLOUD_EXFILTRATION",
        "title": "Apex Wireless confirms corporate breach after threat actors exfiltrate 850,000 subscriber records",
        "summary": "Telecommunications provider Apex Wireless published an official statement confirming attackers accessed internal systems and stole 850,000 subscriber accounts.",
        "content_clean": "Apex Wireless issued an official security notice admitting unauthorized access to its customer management system. The company stated that 850,000 records containing customer names, addresses, and phone numbers were exfiltrated by hackers.",
        "source_name": "SecurityWeek",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Data Breach",
            "claim_status": "confirmed",
            "target_company": "Apex Wireless",
            "claimed_records_count": 850000,
            "min_evidence_score": 50,
        }
    },
    {
        "id": "POS_005_HOSPITAL_OUTAGE",
        "title": "St. Jude Hospital network taken offline by major cyberattack, emergency operations disrupted",
        "summary": "St. Jude Regional Hospital was forced to take electronic health systems offline and divert emergency room ambulances due to a severe cyberattack compromising internal servers.",
        "content_clean": "St. Jude Regional Hospital experienced a catastrophic cyberattack that disrupted hospital infrastructure. Internal hospital networks were compromised and emergency medical operations were crippled. Systems were taken offline to contain the intrusion.",
        "source_name": "The Hacker News",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Major Cyberattack",
            "claim_status": "confirmed",
            "target_company": "St. Jude Regional Hospital",
            "min_evidence_score": 50,
        }
    },
    {
        "id": "POS_006_DEFENSE_RANSOMWARE",
        "title": "LockBit 3.0 ransomware deployed across AeroTech Industries internal servers, halting manufacturing",
        "summary": "LockBit 3.0 deployed ransomware across defense contractor AeroTech Industries, encrypting file servers and halting aircraft component assembly lines.",
        "content_clean": "Defense supplier AeroTech Industries suffered a ransomware attack by LockBit 3.0. Corporate systems were encrypted and manufacturing operations disrupted. The threat actor claims to hold 100GB of proprietary engineering drawings.",
        "source_name": "CyberScoop",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Ransomware",
            "threat_actor": "LockBit 3.0",
            "target_company": "AeroTech Industries",
            "min_evidence_score": 50,
        }
    },
    {
        "id": "POS_007_GOVT_LEAK",
        "title": "State Revenue Portal compromised as hacker forum leaks 120,000 citizen tax identification records",
        "summary": "The State Revenue Department disclosed an unauthorized intrusion into its portal after a cybercriminal forum published 120,000 citizen tax records.",
        "content_clean": "Officials confirmed an intrusion into the State Revenue Portal database. A threat actor exfiltrated 120,000 citizen records and posted them on a breach forum. State authorities notified affected taxpayers.",
        "source_name": "BleepingComputer",
        "expected": {
            "is_cyber": True,
            "decision": "TEAM_ALERT",
            "incident_type": "Data Breach",
            "target_company": "State Revenue Department",
            "claim_status": "confirmed",
            "claimed_records_count": 120000,
            "min_evidence_score": 50,
        }
    },

    # ── NEGATIVE CASES (Must remain strictly WEBSITE_ONLY, NEVER fire a Team Alert) ──
    {
        "id": "NEG_001_PATCH_ADVISORY",
        "title": "Microsoft releases Security Update for Windows Kernel addressing CVE-2026-1122 with Remote Code Execution",
        "summary": "Microsoft has released a patch update fixing an elevation of privilege and remote code execution flaw in the Windows Kernel.",
        "content_clean": "Microsoft Patch Tuesday advisory covers CVE-2026-1122. System administrators are advised to apply the security update promptly. No active enterprise compromise has been reported.",
        "source_name": "Microsoft Security Response Center",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY",
            "incident_type": "Vulnerability",
            "max_evidence_score": 35,
            "cves": ["CVE-2026-1122"]
        }
    },
    {
        "id": "NEG_002_KEV_CATALOG",
        "title": "CISA adds Apple iOS zero-day vulnerability CVE-2026-4488 to Known Exploited Vulnerabilities catalog",
        "summary": "CISA added a new Apple WebKit flaw to the KEV catalog, requiring federal agencies to apply the vendor update within 21 days.",
        "content_clean": "The Cybersecurity and Infrastructure Security Agency (CISA) has added CVE-2026-4488 to its KEV catalog. The advisory urges users to update iOS devices. No specific corporate breach disclosed.",
        "source_name": "CISA Advisories",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY",
            "cves": ["CVE-2026-4488"]
        }
    },
    {
        "id": "NEG_003_RANSOMWARE_REPORT",
        "title": "Annual Cyber Threat Report shows global ransomware payments surged 35% across manufacturing sector",
        "summary": "A comprehensive statistical analysis by cybersecurity researchers highlights trends in ransomware extortion payments during the past calendar year.",
        "content_clean": "According to the annual threat report, ransomware extortion demands increased across the global market. The research paper analyzes extortion tactics, cryptocurrency transactions, and general statistics.",
        "source_name": "SecurityWeek",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_004_PRODUCT_LAUNCH",
        "title": "CrowdStrike launches new Falcon module to protect enterprises against identity-based ransomware attacks",
        "summary": "CrowdStrike announced the general availability of its new Falcon Identity Protection tool designed to prevent credential theft.",
        "content_clean": "CrowdStrike today unveiled a new software product feature to help SOC analysts detect credential harvesting. The marketing announcement showcases product capabilities.",
        "source_name": "TechCrunch Enterprise",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_005_TABLETOP_SIMULATION",
        "title": "Researchers demonstrate hypothetical attack scenario showing how flawed OAuth could allow attackers to bypass MFA in tabletop simulation",
        "summary": "A theoretical study and tabletop exercise demonstrates a potential vulnerability flaw in proof-of-concept testing.",
        "content_clean": "In a simulated breach and tabletop exercise, researchers showed how an attacker could theoretically bypass authentication. The penetration testing writeup was conducted in a lab environment.",
        "source_name": "Dark Reading",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_006_MALWARE_ANALYSIS",
        "title": "Technical deep-dive into the encryption routines and C2 protocol of the new LummaStealer variant",
        "summary": "Security researchers published a reverse-engineering analysis of the LummaStealer payload structure and evasion mechanisms.",
        "content_clean": "This malware analysis report deconstructs the LummaStealer binary. Reverse engineers identified the unpacking stub, API hashing algorithm, and command-and-control communication format.",
        "source_name": "The Hacker News",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_007_AWARENESS_GUIDE",
        "title": "Best practices for implementing phishing awareness training to protect corporate networks from credential theft",
        "summary": "An educational guide detailing how security leaders can conduct effective employee awareness training.",
        "content_clean": "Security awareness training is a cornerstone of defense-in-depth. This guide reviews simulated phishing tests, employee education, and multi-factor authentication hygiene.",
        "source_name": "CSO Online",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_008_EXPLICIT_DENIAL",
        "title": "Global Logistics denies dark web forum claims of database compromise, confirms zero unauthorized access",
        "summary": "Global Logistics issued a formal statement denying claims of a security breach, stating thorough forensic review found no evidence of compromise.",
        "content_clean": "Global Logistics investigated allegations by a threat actor on a hacker forum. The company officially stated: 'We have thoroughly reviewed our systems and confirm there is no evidence of intrusion, no data breach, and no customer data was accessed.'",
        "source_name": "BleepingComputer",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY",
            "claim_status": "denied"
        }
    },
    {
        "id": "NEG_009_HISTORICAL_ANALYSIS",
        "title": "Looking back five years after the Equifax breach: what CISOs learned about patch management",
        "summary": "A retrospective editorial examining the long-term impact of the historical 2017 Equifax data breach on modern cybersecurity policy.",
        "content_clean": "Five years after the historic Equifax compromise, security executives reflect on lessons learned. The historical retrospective reviews the Apache Struts flaw and vulnerability management standards.",
        "source_name": "Dark Reading",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    },
    {
        "id": "NEG_010_ACADEMIC_RESEARCH",
        "title": "Proof-of-concept timing attack on post-quantum lattice-based cryptography schemes",
        "summary": "Academic researchers from Stanford University published a paper demonstrating side-channel timing analysis against Kyber encryption.",
        "content_clean": "An academic research paper presented at the cryptographic conference demonstrates a mathematical side-channel analysis. The theoretical attack requires microsecond timing measurements in a controlled laboratory setting.",
        "source_name": "Cryptology ePrint",
        "expected": {
            "is_cyber": True,
            "decision": "WEBSITE_ONLY"
        }
    }
]
