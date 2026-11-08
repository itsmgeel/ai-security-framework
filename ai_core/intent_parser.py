class IntentParser:
    def __init__(self):
        self.allowed_actions = {"find subdomains": "subfinder -d {target}"}
    def parse_intent(self, user_input: str, target: str) -> str:
        if "find subdomains" in user_input.lower():
            return self.allowed_actions["find subdomains"].format(target=target)
        return "[!] Error: Intent not recognized."
