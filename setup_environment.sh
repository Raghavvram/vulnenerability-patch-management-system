#!/bin/bash
# setup_environment.sh

# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install Ansible
pip install ansible ansible-core
ansible-galaxy collection install community.general

# Install monitoring tools
docker pull grafana/grafana:10.4.2
docker pull prom/prometheus:latest

