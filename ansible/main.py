import logging
from typing import Dict
import yaml

logger = logging.getLogger(__name__)


class AnsiblePlaybookGenerator:
    def __init__(self, llm_analyzer):
        self.llm = llm_analyzer
        self.template_library = self.load_templates()

    def generate_remediation_playbook(self, analysis_data: Dict) -> str:
        """Generate Ansible playbook based on LLM analysis"""

        prompt = f"""
        Generate an Ansible playbook for remediating the following vulnerability:

        Vulnerability: {analysis_data['vulnerability_summary']}
        Affected Service: {analysis_data['service']} v{analysis_data['version']}
        Remediation Steps: {analysis_data['remediation_steps']}
        Priority: {analysis_data['priority']}

        Requirements:
        - Include pre-tasks for backup/snapshot
        - Implement proper error handling
        - Add verification steps
        - Include rollback procedures
        - Follow NIST SP 800-40r4 guidelines
        - Generate in YAML format
        """

        playbook_yaml = self.llm.generate_content(prompt)

        # Validate and sanitize generated YAML
        validated_playbook = self.validate_playbook(playbook_yaml)

        return validated_playbook

    def validate_playbook(self, playbook_content: str) -> str:
        """Validate generated Ansible playbook for security and syntax"""
        try:
            # Parse YAML for syntax validation
            parsed = yaml.safe_load(playbook_content)

            # Security checks
            prohibited_modules = ['shell', 'command', 'raw']
            for play in parsed:
                for task in play.get('tasks', []):
                    if any(module in str(task) for module in prohibited_modules):
                        # Replace with safer alternatives or add constraints
                        task = self.sanitize_task(task)

            # Add mandatory security controls
            enhanced_playbook = self.add_security_controls(parsed)

            return yaml.dump(enhanced_playbook, default_flow_style=False)

        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML generated: {e}")
            return self.fallback_template(playbook_content)

