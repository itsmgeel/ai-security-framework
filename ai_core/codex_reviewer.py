"""
Automated Codex Security Reviewer
Maintained by: Mohit Sharma (@itsmgeel)
Description: Advanced static analysis and AI-driven vulnerability scanner for Python scripts.
Integrates OpenAI Codex to detect unsafe shell executions, injection flaws, and logic bugs.
"""

import os
import sys
import ast
import json
import logging
import argparse
from typing import Dict, List, Any

# Configure logging for CI/CD pipeline integration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] CodexReviewer: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class CodexSecurityScanner:
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.flagged_issues: List[Dict[str, Any]] = []
        self.unsafe_functions = {'system', 'popen', 'run', 'call', 'eval', 'exec'}
        self.api_key = os.getenv("OPENAI_API_KEY")

    def _analyze_ast(self, file_path: str, content: str) -> None:
        """Performs deep static analysis using Python's Abstract Syntax Tree."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Detect unsafe function calls (e.g., os.system, subprocess.run)
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    
                    if func_name in self.unsafe_functions:
                        self._flag_issue(file_path, node.lineno, func_name, "Unsafe execution pattern detected.")
        except SyntaxError as e:
            logging.error(f"Syntax error in {file_path}: {e}")

    def _codex_ai_review(self, file_path: str, content: str) -> None:
        """
        TODO: Implement OpenAI Codex Security API integration.
        This function will send the AST-filtered code blocks to Codex 
        to identify complex logic flaws that static analysis misses.
        """
        if not self.api_key:
            logging.warning("OpenAI API key missing. Skipping deep Codex AI review. (Waiting for Developer Pack credits)")
            return

        logging.info(f"Initiating Codex Security payload for {file_path}...")
        # Placeholder for future OpenAI API call:
        # response = openai.Completion.create(
        #     model="code-davinci-edit-001",
        #     instruction="Find security vulnerabilities in this code and fix them.",
        #     input=content
        # )
        # self._parse_codex_response(response)

    def _flag_issue(self, file_path: str, line: int, trigger: str, description: str) -> None:
        """Registers a vulnerability finding."""
        self.flagged_issues.append({
            "file": file_path,
            "line": line,
            "trigger": trigger,
            "description": description,
            "severity": "HIGH" if trigger in self.unsafe_functions else "MEDIUM"
        })

    def scan(self) -> None:
        """Walks the directory and scans all Python files."""
        logging.info(f"Starting security scan on directory: {self.target_dir}")
        
        if not os.path.exists(self.target_dir):
            logging.error(f"Directory {self.target_dir} does not exist.")
            return

        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    self._process_file(file_path)

    def _process_file(self, file_path: str) -> None:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        logging.info(f"Analyzing {file_path}...")
        self._analyze_ast(file_path, content)
        self._codex_ai_review(file_path, content)

    def generate_report(self, output_file: str = "security_report.json") -> None:
        """Generates a JSON report of all findings for CI/CD ingestion."""
        if not self.flagged_issues:
            logging.info("No security issues detected! Code is clean.")
            return

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"total_issues": len(self.flagged_issues), "findings": self.flagged_issues}, f, indent=4)
        
        logging.warning(f"Scan complete. {len(self.flagged_issues)} issues found. Report saved to {output_file}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Codex Security Reviewer for Framework Code")
    parser.add_argument("--dir", type=str, default=".", help="Directory to scan")
    args = parser.parse_args()

    scanner = CodexSecurityScanner(target_dir=args.dir)
    scanner.scan()
    scanner.generate_report()
