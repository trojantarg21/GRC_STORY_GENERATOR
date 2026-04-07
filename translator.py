TRANSLATION_MAP = {
    "failed_login" : "An attacker attempted to log in but failed",
    "successful_login" : "The attacker successfully logged into the system",
    "privilege_escalation" : "The attacker gained higher access than usual.",
    "file_modification" : "Multiple files were changed in the system.",
    "file_encryption" : "Files are being locked, hinting towards a ransomware attack.",
    "unknown" : "An unknown activity was detected."
}

def translate_event(log):
    event = log.get("event", "unknown")
    ip = log.get("ip")
    message = TRANSLATION_MAP.get(event, TRANSLATION_MAP["unknown"])

    if ip:
        message += f" using the IP address {ip}."
    return {
        "timestamp" : log["timestamp"],
        "translated" : message,
        "event" : event
    }

def translate_logs(parsed_logs):
    translated_logs = []
    
    for log in parsed_logs:
      translated = translate_event(log)
      translated_logs.append(translated)

    return translated_logs
