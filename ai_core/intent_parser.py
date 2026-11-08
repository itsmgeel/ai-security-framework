"""
AI Intent Parser Engine
Maintained by: Mohit Sharma (@itsmgeel)
Description: Advanced Natural Language Processing (NLP) layer that safely translates 
user English prompts into authorized security CLI commands. 
Built to prevent prompt injection and arbitrary command execution.
"""

import re
import json
import logging
from typing import Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - NLP_ENGINE - %(message)s")

class SecurityIntentParser:
    def __init__(self):
        # Strict mapping of allowed actions to prevent arbitrary shell execution
        self.knowledge_base: Dict[str, Dict[str, str]] = self._load_heuristics()
        self.openai_enabled = False  # Toggle once API credits are received

    def _load_heuristics(self) -> Dict[str, Dict[str, str]]:
        """Loads the offline fallback heuristics mapping."""
        return {
            "recon": {
                "subdomains": "subfinder -d {target} -all -silent",
                "directories": "ffuf -w wordlist.txt -u http://{target}/FUZZ",
                "ports": "nmap -p- -sV -sC -T4 {target}"
            },
            "osint": {
                "emails": "theHarvester -d {target} -b all",
                "whois": "whois {target}"
            }
        }

    def _sanitize_target(self, target: str) -> bool:
        """
        Validates target format to prevent command injection (e.g., 'example.com; rm -rf /').
        Strictly allows only valid domain names or IPv4 addresses.
        """
        domain_regex = re.compile(
            r"^(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,6}$"
        )
        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        
        if domain_regex.match(target) or ip_regex.match(target):
            return True
        return False

    def _dynamic_nlp_mapping(self, prompt: str) -> Optional[str]:
        """
        TODO: Integrate OpenAI API to handle complex phrasing.
        Example: "Can you quickly find all the hidden directories for me?"
        This requires NLP to extract intent='directories' and map to ffuf.
        """
        if not self.openai_enabled:
            logging.debug("OpenAI API disabled. Falling back to strict keyword matching.")
            return None
            
        # Placeholder for dynamic API resolution
        # response = openai.ChatCompletion.create(...)
        pass

    def parse_intent(self, user_prompt: str, target: str) -> Tuple[bool, str]:
        """
        Main entry point for intent resolution.
        Takes natural English and returns a safe execution string.
        """
        logging.info(f"Parsing intent for prompt: '{user_prompt}' on target: {target}")
        
        if not self._sanitize_target(target):
            error_msg = f"[CRITICAL] Invalid target format detected: {target}. Aborting to prevent injection."
            logging.error(error_msg)
            return False, error_msg

        prompt_lower = user_prompt.lower()

        # Step 1: Attempt dynamic AI mapping (if funded/enabled)
        ai_command = self._dynamic_nlp_mapping(prompt_lower)
        if ai_command:
            return True, ai_command

        # Step 2: Fallback to heuristic offline matching
        for category, actions in self.knowledge_base.items():
            for keyword, command_template in actions.items():
                if keyword in prompt_lower:
                    safe_command = command_template.format(target=target)
                    logging.info(f"Mapped to {category} category: {safe_command}")
                    return True, safe_command

        msg = "[!] Intent could not be mapped to any authorized security tool. Please rephrase."
        logging.warning(msg)
        return False, msg

if __name__ == "__main__":
    print("===" * 15)
    print(" AI Intent Parser - Security Framework")
    print(" Maintained by: @itsmgeel")
    print("===" * 15)
    
    engine = SecurityIntentParser()
    
    # Test cases demonstrating safety
    test_prompts = [
        ("I need to scan open ports", "scanme.nmap.org"),
        ("find hidden directories", "example.com"),
        ("scan open ports", "example.com; cat /etc/passwd") # Malicious injection attempt
    ]

    for prompt, target in test_prompts:
        print(f"\nUser: {prompt} | Target: {target}")
        success, result = engine.parse_intent(prompt, target)
        if success:
            print(f"System: [+] Authorized Command -> {result}")
        else:
            print(f"System: [-] BLOCKED -> {result}")
