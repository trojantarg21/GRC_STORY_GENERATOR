def generate_summary(translated_logs):
    for log in translated_logs:
        if log.get("event") == "file_encryption":
            return "Critical: A possible ransomware attack has been detected."

        text = log.get("translated", "").lower()
        if "locked" in text or "ransomware" in text or "encrypt" in text:
            return "Critical: A possible ransomware attack has been detected."
        
    return "No major threat detected."

def generate_story(messages):
    entry = []
    action = []
    impact =[]

    for line in messages:
        text = line.lower()
        
        if "unknown activity" in text:
            continue
        elif "log in" in text:
           entry.append(line)
        elif "access" in text or "modified" in text:
           action.append(line)
        elif "locked" in text or "ransomware" in text:
           impact.append(line)
        else:
           action.append(line)
    
    story = ""

    if entry:
        story += "The incident began with " + " ".join(entry) + " "
    else:
        story += "The activity started with suspicious access to the system. "
    
    if action:
        story += "After gaining access, " + " ".join(action) + " "

    if impact:
        story += "This led to serious consequences where " + " ".join(impact) + " "

    return story.strip()

def remove_duplicates(logs):
    cleaned = []
    for log in logs:
        if not cleaned or log != cleaned[-1]:
            cleaned.append(log)
    return cleaned

from collections import defaultdict

def group_events(messages):
    groups = defaultdict(list)

    for msg in messages:
        text = msg.lower()

        if "log in" in text and "couldn't" in text:
            groups["failed_login"].append(msg)
        elif "logged into the system" in text:
            groups["successful_login"].append(msg)
        elif "higher access" in text:
            groups["privilege_escalation"].append(msg)
        elif "modified" in text:
            groups["file_modification"].append(msg)
        elif "locked" in text or "ransomware" in text:
            groups["file_encryption"].append(msg)
        else:
            groups["other"].append(msg)

    return groups

def build_clean_sentences(groups):
    cleaned = []

    if len(groups["failed_login"]) > 1:
        cleaned.append("Multiple failed login attempts were detected.")
    elif len(groups["failed_login"]) == 1:
        cleaned.append(groups["failed_login"][0])

    if len(groups["successful_login"]) > 1:
        cleaned.append("multiple successful logins were observed from different IP addresses.")
    elif len(groups["successful_login"]) == 1:
        cleaned.append(groups["successful_login"][0])

    if groups["privilege_escalation"]:
        cleaned.append("The attacker gained elevated access.")

    if groups["file_modification"]:
        cleaned.append("Several files were modified.")

    if groups["file_encryption"]:
        cleaned.append("files were locked, indicating a ransomware attack.")

    return cleaned

from log_parser import parse_log_file
from translator import translate_logs
from risk_engine import assess_risk, explain_risk, get_recommendations

logs = parse_log_file("raw_logs.txt")
translated = translate_logs(logs)
messages = [log["translated"] for log in translated]
risk = assess_risk(translated)
meaning = explain_risk(risk)
actions = get_recommendations(risk)

groups = group_events(messages)
cleaned_messages = build_clean_sentences(groups)

story = generate_story(cleaned_messages)
summary = generate_summary(translated)

print(summary)
print("\n--- STORY ---\n")
print(story)

print("\n--- RISK ANALYSIS ---\n")
print("RISK LEVEL:", risk)
print("\nWHAT THIS MEANS:")
print(meaning)

print("\nRECOMMENDED ACTIONS:")
for action in actions:
    print("-", action)