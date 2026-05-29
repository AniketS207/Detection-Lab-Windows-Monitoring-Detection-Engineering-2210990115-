import win32evtlog
import yaml
import json
import os
import xml.etree.ElementTree as ET
import ctypes
import sys
import time

DETECTION_FOLDER = "../detections"
ALERT_FILE = "../alerts/alerts.json"

# =========================
# Admin Check
# =========================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    print("[ERROR] Run VS Code as Administrator")
    sys.exit(1)

# =========================
# Load Sigma Rules
# =========================

rules = []

for file in os.listdir(DETECTION_FOLDER):

    if file.endswith(".yml") or file.endswith(".yaml"):

        path = os.path.join(DETECTION_FOLDER, file)

        try:

            with open(path, "r", encoding="utf-8") as f:

                rule = yaml.safe_load(f)

                if rule:
                    rules.append(rule)

        except Exception as e:

            print(f"[ERROR] Failed loading {file}: {e}")

print(f"[+] Loaded {len(rules)} Sigma rules")
print("[+] Starting real-time monitoring...\n")

# =========================
# Sysmon Setup
# =========================

LOG_TYPE = "Microsoft-Windows-Sysmon/Operational"

alerts = []

try:

    query_handle = win32evtlog.EvtQuery(
        LOG_TYPE,
        win32evtlog.EvtQueryReverseDirection,
        "*"
    )

except Exception as e:

    print(f"[ERROR] Failed opening Sysmon log: {e}")
    sys.exit(1)

# =========================
# Field Matching
# =========================

def check_field(field_name, field_value, keywords):

    if isinstance(keywords, str):
        keywords = [keywords]

    field_value = field_value.lower()

    # contains
    if "|contains" in field_name:

        return any(
            keyword.lower() in field_value
            for keyword in keywords
        )

    # endswith
    elif "|endswith" in field_name:

        return any(
            field_value.endswith(keyword.lower())
            for keyword in keywords
        )

    return False

# =========================
# Condition Evaluation
# =========================

def evaluate_condition(condition, results):

    condition = condition.lower()

    # Handle "and not"
    if "and not" in condition:

        parts = condition.split("and not")

        include_part = parts[0].strip()
        exclude_part = parts[1].strip()

        include_names = [x.strip() for x in include_part.split("and")]

        include_match = all(
            results.get(name, False)
            for name in include_names
        )

        exclude_match = results.get(exclude_part, False)

        return include_match and not exclude_match

    # Handle normal AND
    elif " and " in condition:

        names = [x.strip() for x in condition.split("and")]

        return all(
            results.get(name, False)
            for name in names
        )

    # Handle single condition
    else:

        return results.get(condition.strip(), False)

# =========================
# Real-time Monitoring
# =========================

try:

    while True:

        try:

            events = win32evtlog.EvtNext(query_handle, 10)

            if not events:
                time.sleep(1)
                continue

            for event in events:

                try:

                    xml = win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml
                    )

                    root = ET.fromstring(xml)

                    ns = {
                        "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                    }

                    # Event ID
                    event_id_elem = root.find(".//e:EventID", ns)

                    if event_id_elem is None:
                        continue

                    event_id = int(event_id_elem.text)

                    # Sysmon Process Create
                    if event_id != 1:
                        continue

                    # Extract event fields
                    event_data_fields = root.findall(".//e:Data", ns)

                    event_map = {}

                    for field in event_data_fields:

                        name = field.attrib.get("Name", "")
                        value = field.text or ""

                        event_map[name] = value

                    image = event_map.get("Image", "")
                    command_line = event_map.get("CommandLine", "")
                    parent_image = event_map.get("ParentImage", "")

                    # DEBUG OUTPUT
                    #print(f"[DEBUG CMD] {command_line}")

                    # =========================
                    # Sigma Matching
                    # =========================

                    for rule in rules:

                        try:

                            detection = rule.get("detection", {})
                            condition = detection.get("condition", "")

                            results = {}

                            # Process each selection block
                            for block_name, block_content in detection.items():

                                if block_name == "condition":
                                    continue

                                if not isinstance(block_content, dict):
                                    continue

                                matched = True

                                for field_name, keywords in block_content.items():

                                    # Determine field value
                                    if field_name.startswith("Image"):
                                        field_value = image

                                    elif field_name.startswith("CommandLine"):
                                        field_value = command_line

                                    elif field_name.startswith("ParentImage"):
                                        field_value = parent_image

                                    else:
                                        continue

                                    # Match check
                                    if not check_field(
                                        field_name,
                                        field_value,
                                        keywords
                                    ):
                                        matched = False
                                        break

                                results[block_name] = matched

                            # Evaluate Sigma condition
                            final_match = evaluate_condition(
                                condition,
                                results
                            )

                            # Alert
                            if final_match:

                                alert = {
                                    "rule_name": rule.get("title", "Unnamed Rule"),
                                    "severity": rule.get("level", "unknown"),
                                    "event_id": event_id,
                                    "image": image,
                                    "parent_image": parent_image,
                                    "command_line": command_line,
                                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                                }

                                alerts.append(alert)

                                print("\n===================================")
                                print(f"[ALERT] {alert['rule_name']}")
                                print(f"Severity : {alert['severity']}")
                                print(f"Image    : {image}")
                                print(f"Parent   : {parent_image}")
                                print(f"Command  : {command_line}")
                                print("===================================\n")

                        except Exception as e:

                            print(f"[ERROR] Rule match failed: {e}")

                except Exception as e:

                    print(f"[ERROR] Event processing failed: {e}")

        except KeyboardInterrupt:

            print("\n[+] Monitoring stopped.")
            break

        except Exception as e:

            print(f"[ERROR] Event loop failed: {e}")
            time.sleep(1)

except KeyboardInterrupt:

    print("\n[+] Monitoring stopped.")

# =========================
# Save Alerts
# =========================

os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)

try:

    with open(ALERT_FILE, "w", encoding="utf-8") as f:

        json.dump(alerts, f, indent=4)

    print(f"[+] Saved {len(alerts)} alerts to {ALERT_FILE}")

except Exception as e:

    print(f"[ERROR] Failed saving alerts: {e}")