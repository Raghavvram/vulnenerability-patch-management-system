# llm_service/output_validator.py

import re
import logging
import html

logger = logging.getLogger(__name__)


class OutputValidator:
    def __init__(self):
        self.allowed_remediation_patterns = self.load_safe_patterns()
        self.dangerous_output_patterns = self.load_dangerous_patterns()

    def is_safe_remediation_step(self, step: str) -> bool:
        """Validate that remediation step is safe to execute"""

        # Check against dangerous command patterns
        dangerous_patterns = [
            r"rm\s+-rf",
            r"format\s+c:",
            r"del\s+/f",
            r"shutdown",
            r"reboot\s+now",
            r"dd\s+if=",
            r"curl.*\|\s*sh",
            r"wget.*\|\s*bash"
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, step, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected in remediation step: {step}")
                return False

        # Validate against whitelist of safe patterns
        safe_patterns = [
            r"update\s+package",
            r"install\s+patch",
            r"configure\s+service",
            r"restart\s+service",
            r"apply\s+security\s+update",
            r"set\s+configuration"
        ]

        for pattern in safe_patterns:
            if re.search(pattern, step, re.IGNORECASE):
                return True

        # Default to safe if unclear
        return True

    def sanitize_text(self, text: str) -> str:
        """Sanitize text output from LLM"""

        # HTML encode to prevent XSS
        sanitized = html.escape(text)

        # Remove potential script tags
        sanitized = re.sub(r'<script.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)

        # Limit length
        return sanitized[:2000]

