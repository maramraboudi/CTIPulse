CURATED_MAPPINGS = {
    "CVE-2021-44228": [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "evidence": "The vulnerability existed in an internet-facing Java logging component.", "confidence": "high"},
        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution", "evidence": "Public exploitation has used injected expressions to execute code in some deployments.", "confidence": "medium"},
    ],
    "CVE-2021-34527": [
        {"technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "evidence": "Print Spooler remote exploitation can enable lateral movement.", "confidence": "high"},
        {"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "evidence": "The flaw can allow elevation of privileges.", "confidence": "high"},
    ],
    "CVE-2023-38831": [
        {"technique_id": "T1204.002", "technique_name": "User Execution: Malicious File", "tactic": "Execution", "evidence": "Public exploits relied on archive content presented to a user.", "confidence": "medium"},
    ],
    "CVE-2023-34362": [
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "evidence": "MOVEit Transfer is a public-facing file transfer service.", "confidence": "high"},
    ],
}


def mappings_for(cve_id: str) -> list[dict]:
    return CURATED_MAPPINGS.get(cve_id, [])
