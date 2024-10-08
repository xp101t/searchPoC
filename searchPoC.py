# Search GitHub for PoC with CVE by xp101t

import os
import json
import re
import sys

header_art = """
   _____                      __       ____        ______
  / ___/___  ____ ___________/ /_     / __ \____  / ____/
  \__ \/ _ \/ __ `/ ___/ ___/ __ \   / /_/ / __ \/ /     
 ___/ /  __/ /_/ / /  / /__/ / / /  / ____/ /_/ / /___   
/____/\___/\__,_/_/   \___/_/ /_/  /_/    \____/\____/   
"""


# Check if the provided CVE ID is in the correct format
def is_valid_cve(cve):
    return re.match(r"CVE-\d{4}-\d{4,7}$", cve) is not None

# Search for PoCs in the provided base directory
def search_pocs(cve_list, base_dir):
    found_pocs = {}
    not_returned_cves = []
    
    # List of keywords that indicate remediation or detection scripts
    exclusion_keywords = [
        "mitigation", "remediation", "detection", "fix", "patch",
        "workaround", "bypass", "prevent", "secure", "protection",
        "defense", "harden", "safeguard", "fortify", "remediate", 
        "alleviate", "resolve", "shield", "uncover vulnerabilities", 
        "detect vulnerabilities", "diagnose", "analysis"
    ]
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.json'):
                file_cve = file.replace('.json', '')
                if file_cve in cve_list:
                    cve_path = os.path.join(root, file)
                    with open(cve_path, 'r') as json_file:
                        try:
                            data = json.load(json_file)
                            found_valid_poc = False
                            temp_pocs = []

                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict):
                                        description = (item.get("description") or "").lower()
                                        html_url = item.get("html_url", "").lower()
                                        if not description or any(keyword in description for keyword in exclusion_keywords):
                                            continue
                                        if "poc" in description or "poc" in html_url:
                                            found_pocs[file_cve] = {
                                                "html_url": item.get("html_url"),
                                                "description": item.get("description")
                                            }
                                            found_valid_poc = True
                                            break
                                        temp_pocs.append({
                                            "html_url": item.get("html_url"),
                                            "description": item.get("description")
                                        })

                            elif isinstance(data, dict):
                                description = (data.get("description") or "").lower()
                                html_url = data.get("html_url", "").lower()
                                if not description or any(keyword in description for keyword in exclusion_keywords):
                                    continue
                                if "poc" in description or "poc" in html_url:
                                    found_pocs[file_cve] = {
                                        "html_url": data.get("html_url"),
                                        "description": data.get("description")
                                    }
                                    found_valid_poc = True
                                else:
                                    temp_pocs.append({
                                        "html_url": data.get("html_url"),
                                        "description": data.get("description")
                                    })
                            
                            if not found_valid_poc and temp_pocs:
                                found_pocs[file_cve] = temp_pocs[0]
                            elif not found_valid_poc:
                                not_returned_cves.append(file_cve)
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON for {file_cve}")
    
    return found_pocs, not_returned_cves

# Find the base directory for searching PoCs
def find_base_dir(base_dir_name='PoC-in-GitHub'):
    possible_dirs = [
        os.path.join(os.getcwd(), base_dir_name),
        os.path.join(os.getcwd(), '..', base_dir_name),
        os.path.join(os.getcwd(), '..', '..', base_dir_name)
    ]
    
    for directory in possible_dirs:
        if os.path.isdir(directory):
            return directory
    
    return None

def main(cve_input=None):
    print(header_art)
    print("Search GitHub for PoC with CVE\nForged by xp101t")

    base_dir = find_base_dir()
    
    if base_dir is None:
        print(f"Error: Directory 'PoC-in-GitHub' not found in the current or parent directories.")
        return
    
    if cve_input is None:
        cve_input = input("\nEnter CVEs separated by spaces or commas: ")
    
    cve_list = [cve.strip() for cve in re.split(r'[,\s]+', cve_input) if is_valid_cve(cve.strip())]
    
    if not cve_list:
        print("No valid CVEs provided.")
        return

    pocs, not_returned_cves = search_pocs(cve_list, base_dir)
    
    if pocs:
        print("---------------------------------------------------------------------------------\nPoC('s) found:")
        for cve, info in pocs.items():
            print()
            description = info['description'] if info['description'] else "Description not available"
            html_url = info['html_url'] if info['html_url'] else "URL not available"
            
            if "poc" in description.lower():
                print(f"\033[93m\033[91m{cve}\033[0m\033[0m: {description}")
            else:
                print(f"\033[91m{cve}\033[0m: {description}")
                
            print(html_url)
    
    if not_returned_cves:
        print("---------------------------------------------------------------------------------\nPotential false positive(s), description flagged remediation/detection/null:\n")
        for cve in not_returned_cves:
            print(f"\033[91m{cve}\033[0m")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cve_input = ' '.join(sys.argv[1:])
        main(cve_input)
    else:
        main()