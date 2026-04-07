def assess_risk(translated_logs):
    risk = "LOW"

    for log in translated_logs:
        event = log.get("event", "")
        text = log.get("translated", "").lower()

        # 🔴 HIGH priority
        if event == "file_encryption" or "ransomware" in text or "locked" in text:
            return "HIGH"

        # 🟡 MEDIUM
        elif event == "privilege_escalation":
            risk = "MEDIUM"

        elif event == "failed_login":
            if risk != "MEDIUM":
                risk = "LOW"

    return risk

def explain_risk(risk):
    if risk == "HIGH":
        return "The system is under active attack and damage is likely occurring."
    elif risk == "MEDIUM":
        return "Suspicious activity detected that could lead to a security breach."
    else:
        return "No significant threat detected this time." 
    
def get_recommendations(risk):
    if risk == "HIGH":
        return [
            "Disconnect affected systems immediately",
            "Inform the security team",
            "Check backups and restore critical data",
            "Investigate how the attack started"
        ]

    elif risk == "MEDIUM":
        return [
            "Monitor user activity closely",
            "Verify access permissions",
            "Investigate unusual behavior"
        ]

    else:
        return [
            "No immediate action required",
            "Continue monitoring system activity"
        ]