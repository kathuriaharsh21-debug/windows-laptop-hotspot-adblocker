"""
generate_extension_rules.py
Converts the blocklist into Chrome declarativeNetRequest JSON rules (max 30,000 static rules).
Run this once to regenerate extension/rules/ad_domains.json.
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services'))
from blocklist_loader import load_blocklist

def main():
    print("Loading blocklist...")
    bl = load_blocklist()
    domains = sorted(bl)[:30000]  # Chrome MV3 max static rules

    rules = []
    for i, domain in enumerate(domains, 1):
        rules.append({
            "id": i,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": f"||{domain}^",
                "resourceTypes": [
                    "main_frame","sub_frame","stylesheet","script",
                    "image","font","object","xmlhttprequest",
                    "ping","csp_report","media","websocket","other"
                ]
            }
        })

    out_dir = os.path.join(os.path.dirname(__file__), '..', 'extension', 'rules')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'ad_domains.json')
    with open(out_path, 'w') as f:
        json.dump(rules, f)
    print(f"Written {len(rules):,} rules to {out_path}")

if __name__ == '__main__':
    main()
