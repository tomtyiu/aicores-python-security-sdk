##Creator Thomas Yiu and OpenAI o1

import subprocess
import sys
from pathlib import Path
from typing import Optional
import logging


class SecurityScanner:
    """
    A security scanning SDK for Python projects that integrates pip-audit, Safety, and Bandit.
    """

    def __init__(self):
        # Configure logging
        logging.basicConfig(
            filename='security_scanner.log',
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        # Verify that required tools are installed
        self._verify_tool_installed('pip-audit', ['pip-audit', '--version'])
        self._verify_tool_installed('safety', ['safety', '--version'])
        # Bandit will be verified later based on virtual environment status

    def _verify_tool_installed(self, tool_name: str, check_command: list):
        """
        Verifies if a tool is installed by running its version command.
        """
        try:
            subprocess.run(check_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"{tool_name} is installed.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            error_msg = f"Error: {tool_name} is not installed or not found in PATH.\n" \
                        f"Please install {tool_name} using 'pip install {tool_name}' and ensure it's in your PATH."
            print(error_msg)
            logging.error(error_msg)
            sys.exit(1)

    def _is_virtual_environment(self) -> bool:
        """
        Checks if the current Python interpreter is running inside a virtual environment.
        """
        return sys.prefix != sys.base_prefix

    def run_pip_audit(self) -> Optional[str]:
        """
        Runs pip-audit to check for vulnerabilities in dependencies.

        Returns:
            The output of pip-audit as a string if successful, else None.
        """
        print("Running pip-audit...\n")
        logging.info("Running pip-audit.")
        try:
            result = subprocess.run(['pip-audit'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("pip-audit Results:\n")
            print(result.stdout)
            logging.info("pip-audit completed successfully.")
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"pip-audit encountered an error:\n{e.stderr}"
            print(error_msg)
            logging.error(error_msg)
            return None

    def run_safety(self) -> Optional[str]:
        """
        Runs Safety to check for vulnerabilities in dependencies.

        Returns:
            The output of Safety as a string if successful, else None.
        """
        print("Running Safety...\n")
        logging.info("Running Safety.")
        try:
            # Using safety check command with full report
            result = subprocess.run(['safety', 'check', '--full-report'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("Safety Results:\n")
            print(result.stdout)
            logging.info("Safety completed successfully.")
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Safety returns exit code 1 if vulnerabilities are found
            if e.returncode == 1:
                warning_msg = f"Safety found vulnerabilities:\n{e.stdout}"
                print(warning_msg)
                logging.warning(warning_msg)
                return e.stdout
            else:
                error_msg = f"Safety encountered an error:\n{e.stderr}"
                print(error_msg)
                logging.error(error_msg)
                return None

    def run_bandit(self, file_path: Path) -> Optional[str]:
        """
        Runs Bandit on the specified Python file or directory within a virtual environment.

        Args:
            file_path (Path): The path to the Python file or directory to scan.

        Returns:
            The output of Bandit as a string if successful, else None.
        """
        if not self._is_virtual_environment():
            error_msg = "Error: Bandit must be run inside a virtual environment.\n" \
                        "Please activate your virtual environment and ensure Bandit is installed within it."
            print(error_msg)
            logging.error(error_msg)
            return None

        if not file_path.exists():
            error_msg = f"Error: The file or directory '{file_path}' does not exist."
            print(error_msg)
            logging.error(error_msg)
            return None

        print(f"Running Bandit on '{file_path}'...\n")
        logging.info(f"Running Bandit on '{file_path}'.")
        try:
            # Use 'python -m bandit' instead of 'bandit' to ensure the correct executable is used
            command = [sys.executable, '-m', 'bandit', '-r', str(file_path)]
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("Bandit Results:\n")
            print(result.stdout)
            logging.info("Bandit completed successfully.")
            return result.stdout
        except subprocess.CalledProcessError as e:
            # Bandit returns non-zero exit codes based on findings or errors
            if e.returncode == 1:
                warning_msg = f"Bandit found issues:\n{e.stdout}"
                print(warning_msg)
                logging.warning(warning_msg)
            else:
                error_msg = f"Bandit encountered an error:\n{e.stderr}"
                print(error_msg)
                logging.error(error_msg)
            return e.stdout if e.stdout else e.stderr

    def prompt_and_run_bandit(self) -> Optional[str]:
        """
        Prompts the user for a Python file or directory path and runs Bandit on it within a virtual environment.

        Returns:
            The output of Bandit as a string if successful, else None.
        """
        file_path_input = input("Enter the path to the Python file or directory you want to scan with Bandit: ").strip()
        file_path = Path(file_path_input)

        return self.run_bandit(file_path)

    def run_all_scans(self):
        """
        Runs all security scans: pip-audit, Safety, and Bandit.
        """
        print("Starting all security scans...\n")
        logging.info("Starting all security scans.")
        self.run_pip_audit()
        print("\n-----------------------------------\n")
        self.run_safety()
        print("\n-----------------------------------\n")
        self.prompt_and_run_bandit()
        print("\nSecurity scans completed.")
        logging.info("All security scans completed.")


if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_all_scans()
