# Search GitHub for PoC with CVE by xp101t

import os
import json
import re
import sys

def is_valid_cve(cve):
    return re.match(r"CVE-\d{4}-\d{4,7}$", cve) is not None

def search_pocs(cve_list, base_dir):
    found_pocs = {}
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.json'):
                file_cve = file.replace('.json', '')
                if file_cve in cve_list:
                    cve_path = os.path.join(root, file)
                    with open(cve_path, 'r') as json_file:
                        try:
                            data = json.load(json_file)
                            if isinstance(data, list):
                                html_urls = [item.get("html_url") for item in data if isinstance(item, dict)]
                                descriptions = [item.get("description") for item in data if isinstance(item, dict)]
                                found_pocs[file_cve] = {
                                    "html_url": html_urls[0] if html_urls else None,
                                    "description": descriptions[0] if descriptions else None
                                }
                            elif isinstance(data, dict):
                                found_pocs[file_cve] = {
                                    "html_url": data.get("html_url"),
                                    "description": data.get("description")
                                }
                            else:
                                found_pocs[file_cve] = {
                                    "html_url": None,
                                    "description": None
                                }
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON for {file_cve}")
    
    return found_pocs

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
    base_dir = find_base_dir()
    
    if base_dir is None:
        print(f"Error: Directory 'PoC-in-GitHub' not found in the current or parent directories.")
        return
    
    if cve_input is None:
        cve_input = input("Enter CVEs separated by spaces or commas: ")
    
    cve_list = [cve.strip() for cve in re.split(r'[,\s]+', cve_input) if is_valid_cve(cve.strip())]
    
    if not cve_list:
        print("No valid CVEs provided.")
        return

    pocs = search_pocs(cve_list, base_dir)
    
    if pocs:
        for cve, info in pocs.items():
            print()
            description = info['description'] if info['description'] else "Description not available"
            html_url = info['html_url'] if info['html_url'] else "URL not available"
            
            print(f"\033[91m{cve}\033[0m: {description}")
            print(html_url)
    else:
        print("No PoCs found for the given CVEs.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cve_input = ' '.join(sys.argv[1:])
        main(cve_input)
    else:
        main()
