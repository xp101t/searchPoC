# Search GitHub for PoC with CVE by xp101t

import subprocess
import os
import sys

def run_command(command, cwd=None):
    """Run a shell command and print its output."""
    try:
        result = subprocess.run(command, shell=True, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{command}': {e}", file=sys.stderr)
        sys.exit(1)

def update_repo(repo_path):
    """Update the cloned GitHub repository."""
    if not os.path.isdir(repo_path):
        print(f"Repository path '{repo_path}' does not exist.")
        sys.exit(1)

    print(f"Updating repository at {repo_path}...")
    
    # Navigate to the repository directory
    os.chdir(repo_path)
    
    # Fetch the latest changes from the remote repository
    run_command('git fetch')

    # Pull the latest changes from the remote branch
    run_command('git pull')

def main():
    repo_url = "https://github.com/nomi-sec/PoC-in-GitHub"
    repo_name = repo_url.split('/')[-1]
    repo_path = os.path.join(os.getcwd(), repo_name)

    # Check if the repository directory exists
    if os.path.isdir(repo_path):
        update_repo(repo_path)
    else:
        print(f"Cloning repository from {repo_url}...")
        # Clone the repository if it does not exist
        run_command(f'git clone {repo_url}')
        update_repo(repo_path)

if __name__ == "__main__":
    main()
