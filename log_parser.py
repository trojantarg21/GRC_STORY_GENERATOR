import re

def parse_log_line(line):
    log_pattern = r"^(.*?) - (.*)$"
    match = re.match(log_pattern,line)
    if not match:
        return None
    
    timestamp = match.group(1)
    message = match.group(2)

    log_data = {
        "timestamp" : timestamp,
        "message" : message,
        "event" : None,
        "ip" : None
    }

    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", message)
    if ip_match:
        log_data["ip"] = ip_match.group()

    message_lower = message.lower()   
    if "failed login" in message_lower:
        log_data["event"] = "failed_login"
    elif "successful login" in message_lower:
        log_data["event"] = "successful_login"
    elif "privileges escalated" in message_lower:
        log_data["event"] = "privilege_escalation"
    elif "files modified" in message_lower:
        log_data["event"] = "file_modification"
    elif "encrypt" in message_lower:
        log_data["event"] = "file_encryption"
    else:
        log_data["event"] = "unknown"
  
    return log_data

def parse_log_file(file_path):
    parsed_logs = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip().replace("\r", "")
            if line:
                parsed = parse_log_line(line)
                if parsed:
                    parsed_logs.append(parsed)
   
    return parsed_logs
