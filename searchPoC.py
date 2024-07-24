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
                                # Check each item in the list
                                html_urls = [item.get("html_url") for item in data if isinstance(item, dict)]
                                # If multiple urls, you might want to pick one or handle differently
                                found_pocs[file_cve] = html_urls[0] if html_urls else None
                            elif isinstance(data, dict):
                                found_pocs[file_cve] = data.get("html_url")
                            else:
                                found_pocs[file_cve] = None
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON for {file_cve}")
    
    return found_pocs

def main(cve_input=None):
    base_dir = 'PoC-in-GitHub'  # Change this if the repo is in a different location
    
    if cve_input is None:
        cve_input = input("Enter CVEs separated by commas: ")
    
    cve_list = [cve.strip() for cve in cve_input.split(',') if is_valid_cve(cve.strip())]
    
    if not cve_list:
        print("No valid CVEs provided.")
        return

    pocs = search_pocs(cve_list, base_dir)
    
    if pocs:
        for cve, url in pocs.items():
            if url:
                print(f"\033[1;35mFound PoC for {cve}:\033[0m {url}")
            else:
                print(f"\033[1;33mFound PoC for {cve}, but 'html_url' is missing.\033[0m")
    else:
        print("No PoCs found for the given CVEs.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cve_input = ','.join(sys.argv[1:])
        main(cve_input)
    else:
        main()

