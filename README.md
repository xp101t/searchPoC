# searchPoC
Search GitHub for PoC with CVE by xp101t

Vuln scans can output hundreds of CVEs, I made this tool to quickly learn which CVEs have PoCs on GitHub.

Instructions
1. Clone PoC in GitHub repo, not mine, all credit to nomi-sec

<code>git clone https://github.com/nomi-sec/PoC-in-GitHub.git</code>

2. Clone this GithHub repo to the same directory (Note: if repos are in different directories, you will need to change base_dir in searchPoC.py)

<code>git clone https://github.com/xp101t/searchPoC.git</code>

3. Search GitHub for PoC with CVE (You will be prompted for CVE if you don't pass as arg)

<code>python3 searchPoC/searchPoC.py <CVEs seperated by spaces or commas> </code>

I also made a script to update nomi-sec's PoC in GitHub repo
<code>python3 searchPoC/updatePoC.py</code>

<code>python3 updatePoC.py</code>

Example:
Clone both repos to the same directory
![image](https://github.com/user-attachments/assets/e0ed4911-c7e0-45c8-91eb-08f0b8fb31e8)

Example with CVEs passed as arg
![image](https://github.com/user-attachments/assets/2d77a0a7-d0e0-4f71-aa2a-6bca9db5105a)

Example with CVEs inputed after prompt
![image](https://github.com/user-attachments/assets/092ac885-20e9-49c1-82f1-85b47f728928)
