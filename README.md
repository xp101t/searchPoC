# searchPoC
Search GitHub for PoC with CVE by xp101t

Vuln scans can output hundreds of CVEs, I made this tool to quickly learn which CVEs have PoCs on GitHub.

Instructions:

1. Clone repo

<code>git clone https://github.com/xp101t/searchPoC.git</code>

2. Clone/update nomi-sec's "PoC-in-GitHub" repo

<code>python3 updatePoC.py</code>

3. Search GitHub for PoC with CVE (You will be prompted for CVE if you don't pass as arg)

<code>python3 searchPoC.py <CVEs seperated by spaces or commas> </code>
