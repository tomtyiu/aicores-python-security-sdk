import subprocess
import sys
from pathlib import Path
from typing import Optional

class SecurityScanner:
    """
    A security scanning SDK for Python projects that integrates pip-audit, Safety, and Bandit.
    """

    def __init__(self):
        # Verify that required tools are installed
        self._verify_tool_installed('pip-audit', ['pip-audit', '--version'])
        self._verify_tool_installed('safety', ['safety', '--version'])
        self._verify_tool_installed('bandit', ['bandit', '--version'])

    def _verify_tool_installed(self, tool_name: str, check_command: list):
        """
        Verifies if a tool is installed by running its version command.
        """
        try:
            subprocess.run(check_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"Error: {tool_name} is not installed or not found in PATH.")
            print(f"Please install {tool_name} using 'pip install {tool_name}' and ensure it's in your PATH.")
            sys.exit(1)

    def run_pip_audit(self) -> Optional[str]:
        """
        Runs pip-audit to check for vulnerabilities in dependencies.

        Returns:
            The output of pip-audit as a string if successful, else None.
        """
        print("Running pip-audit...")
        try:
            result = subprocess.run(['pip-audit'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print("pip-audit encountered an error:")
            print(e.stderr)
            return None

    def run_safety(self) -> Optional[str]:
        """
        Runs Safety to check for vulnerabilities in dependencies.

        Returns:
            The output of Safety as a string if successful, else None.
        """
        print("Running Safety...")
        try:
            # Using safety check command; adjust arguments as needed
            result = subprocess.run(['safety', 'check'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Safety returns exit code 1 if vulnerabilities are found
            if e.returncode == 1:
                print("Safety found vulnerabilities:")
                print(e.stdout)
                return e.stdout
            else:
                print("Safety encountered an error:")
                print(e.stderr)
                return None

    def prompt_and_run_bandit(self) -> Optional[str]:
        """
        Prompts the user for a Python file path and runs Bandit on the specified file.

        Returns:
            The output of Bandit as a string if successful, else None.
        """
        file_path = input("Enter the path to the Python file you want to scan with Bandit: ").strip()
        path = Path(file_path)

        if not path.is_file():
            print(f"Error: The file '{file_path}' does not exist.")
            return None

        print(f"Running Bandit on {file_path}...")
        try:
            result = subprocess.run(['bandit', '-r', str(path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Bandit returns non-zero exit codes based on findings or errors
            print("Bandit completed with findings or encountered an error:")
            print(e.stdout)
            print(e.stderr)
            return e.stdout if e.stdout else e.stderr

    def run_all_scans(self):
        """
        Runs all security scans: pip-audit, Safety, and Bandit.
        """
        print("Starting all security scans...\n")
        self.run_pip_audit()
        print("\n-----------------------------------\n")
        self.run_safety()
        print("\n-----------------------------------\n")
        self.prompt_and_run_bandit()
        print("\nSecurity scans completed.")

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_all_scans()
