# Ansible Installation Guide

Ansible is a free and open-source agentless automation platform for configuration management, application deployment, and task automation across multiple systems. Originally developed by Michael DeHaan and acquired by Red Hat, Ansible serves as the industry standard for infrastructure automation with enterprise-grade security and scalability. It provides a robust alternative to proprietary solutions like VMware vRealize Automation, Microsoft System Center, or Puppet Enterprise without vendor lock-in or licensing costs.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2+ cores for control machine (4+ cores recommended for large deployments)
  - RAM: 2GB minimum, 4GB+ recommended for large infrastructures, 8GB+ for enterprise
  - Storage: 10GB+ available disk space for playbooks, roles, and logs
  - Network: Stable connectivity to all managed hosts
- **Operating System** (Control Machine): 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, openSUSE)
  - macOS: 10.15+ (Catalina or newer)
  - Windows: WSL2 with Linux distribution (not natively supported)
  - FreeBSD: 12.0+ (limited support)
- **Target Hosts**:
  - Linux: Any distribution with Python 2.7+ or 3.5+
  - Windows: PowerShell 3.0+ and .NET Framework 4.0+
  - Network devices: SSH or specialized connection plugins
- **Network Requirements**:
  - SSH access to target Linux/Unix hosts (port 22)
  - WinRM access to Windows hosts (ports 5985/5986)
  - HTTPS API access for cloud and network devices
- **Dependencies**:
  - Python 3.8+ on control machine (3.9+ recommended)
  - SSH client and key-based authentication setup
  - Python 2.7+ or 3.5+ on target Linux hosts
  - PowerShell and .NET Framework on Windows targets
- **System Access**: SSH key access or password authentication to target hosts
- **Special Requirements**:
  - Sudo or root access on target systems for privileged operations
  - Network connectivity between control machine and all managed hosts


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### Using Package Manager (Recommended)

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Ansible and dependencies
sudo apt install -y ansible python3-pip python3-venv sshpass

# Install additional collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install kubernetes.core
ansible-galaxy collection install amazon.aws
ansible-galaxy collection install azure.azcollection
ansible-galaxy collection install google.cloud

# Verify installation
ansible --version
ansible-galaxy collection list
```

#### RHEL/CentOS/Rocky Linux/AlmaLinux
```bash
# Install EPEL repository
sudo yum install -y epel-release

# Install Ansible
sudo yum install -y ansible python3-pip

# For newer distributions
sudo dnf install -y ansible python3-pip

# Install collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install kubernetes.core

# Verify installation
ansible --version
```

#### Fedora
```bash
# Install Ansible
sudo dnf install -y ansible python3-pip python3-virtualenv

# Install additional collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install kubernetes.core

# Verify installation
ansible --version
```

#### Arch Linux
```bash
# Install Ansible
sudo pacman -Syu ansible python-pip

# Install collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix

# Verify installation
ansible --version
```

#### Alpine Linux
```bash
# Install Ansible
sudo apk update
sudo apk add ansible python3 py3-pip openssh

# Install collections
ansible-galaxy collection install community.general

# Verify installation
ansible --version
```

#### openSUSE/SLES
```bash
# openSUSE Leap/Tumbleweed
sudo zypper refresh

# Install Ansible and dependencies
sudo zypper install -y ansible python3-pip python3-virtualenv

# SLES 15 (requires additional modules)
sudo SUSEConnect -p sle-module-python3/15.5/x86_64
sudo zypper install -y ansible python3-pip

# Install additional collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install kubernetes.core

# Verify installation
ansible --version
```

#### macOS
```bash
# Method 1: Using Homebrew (recommended)
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Ansible
brew install ansible

# Method 2: Using pip with virtual environment
# Install Python 3 if needed
brew install python3

# Create virtual environment
python3 -m venv ~/ansible-venv
source ~/ansible-venv/bin/activate

# Install Ansible
pip install --upgrade pip
pip install ansible ansible-core

# Install additional packages for cloud providers
pip install boto3 azure-cli google-cloud-storage

# Add to shell profile for persistence
echo 'source ~/ansible-venv/bin/activate' >> ~/.zshrc  # or ~/.bash_profile

# Install collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install amazon.aws
ansible-galaxy collection install azure.azcollection

# Verify installation
ansible --version
```

#### FreeBSD
```bash
# Install from ports
cd /usr/ports/sysutils/ansible && make install clean

# Or install from packages
pkg install py39-ansible

# Install Python dependencies
pkg install python39 py39-pip py39-virtualenv

# Create virtual environment (recommended)
python3.9 -m venv ~/ansible-venv
source ~/ansible-venv/bin/activate

# Install additional packages
pip install paramiko jinja2 PyYAML cryptography

# Install collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix

# Verify installation
ansible --version
```

#### Windows (using WSL2)
```powershell
# Enable WSL2 first
# Run in PowerShell as Administrator
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Restart computer, then set WSL2 as default
wsl --set-default-version 2

# Install Ubuntu from Microsoft Store or command line
wsl --install -d Ubuntu-22.04

# Inside WSL Ubuntu environment:
sudo apt update
sudo apt install -y ansible python3-pip python3-venv sshpass

# Create Windows-specific inventory for managing Windows hosts
mkdir -p ~/ansible-windows
cd ~/ansible-windows

# Install Windows collections
ansible-galaxy collection install ansible.windows
ansible-galaxy collection install community.windows
ansible-galaxy collection install chocolatey.chocolatey

# Create Windows inventory example
cat > inventory/windows-hosts.yml <<EOF
all:
  children:
    windows:
      hosts:
        win-server-01:
          ansible_host: 192.168.1.100
          ansible_user: Administrator
          ansible_password: "{{ vault_windows_password }}"
          ansible_connection: winrm
          ansible_winrm_server_cert_validation: ignore
          ansible_winrm_transport: basic
          ansible_winrm_port: 5985
      vars:
        ansible_shell_type: powershell
        ansible_become_method: runas
        ansible_become_user: Administrator
EOF

# Verify installation
ansible --version
```

### Using pip (Latest Version)
```bash
# Create virtual environment (recommended)
python3 -m venv ~/ansible-venv
source ~/ansible-venv/bin/activate

# Install Ansible via pip
pip install --upgrade pip
pip install ansible ansible-core

# Install additional packages
pip install paramiko jinja2 PyYAML cryptography

# Install cloud provider SDKs
pip install boto3 botocore azure-cli google-cloud-storage

# Install collections
ansible-galaxy collection install community.general
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install kubernetes.core
ansible-galaxy collection install amazon.aws
ansible-galaxy collection install azure.azcollection
ansible-galaxy collection install google.cloud

# Add to PATH permanently
echo 'source ~/ansible-venv/bin/activate' >> ~/.bashrc

# Verify installation
ansible --version
```

### Using Docker
```bash
# Create Ansible Docker container with mounted volumes
docker run --rm -it \
  -v $(pwd):/ansible \
  -v ~/.ssh:/root/.ssh:ro \
  -v ~/.aws:/root/.aws:ro \
  -v ~/.azure:/root/.azure:ro \
  --workdir /ansible \
  ansible/ansible:latest

# Create wrapper script for ease of use
sudo tee /usr/local/bin/ansible-docker > /dev/null <<'EOF'
#!/bin/bash
docker run --rm -it \
  -v $(pwd):/ansible \
  -v ~/.ssh:/root/.ssh:ro \
  -v ~/.aws:/root/.aws:ro \
  -v ~/.azure:/root/.azure:ro \
  -v ~/.kube:/root/.kube:ro \
  --workdir /ansible \
  --network host \
  ansible/ansible:latest "$@"
EOF
sudo chmod +x /usr/local/bin/ansible-docker

# Create aliases
echo 'alias ansible="ansible-docker ansible"' >> ~/.bashrc
echo 'alias ansible-playbook="ansible-docker ansible-playbook"' >> ~/.bashrc
```

## Initial Configuration

### First-Run Setup

1. **SSH Key Setup**:
```bash
# Generate SSH key pair for Ansible
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ansible_key -C "ansible-automation"

# Set proper permissions
chmod 600 ~/.ssh/ansible_key
chmod 644 ~/.ssh/ansible_key.pub

# Copy public key to target hosts
ssh-copy-id -i ~/.ssh/ansible_key.pub user@target-host

# Or manually copy the key
cat ~/.ssh/ansible_key.pub | ssh user@target-host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

2. **Basic Ansible Configuration**:
```bash
# Create Ansible configuration directory
mkdir -p ~/.ansible/{facts_cache,inventory_cache,cp,logs}

# Create basic ansible.cfg
cat > ~/.ansible.cfg <<EOF
[defaults]
host_key_checking = True
remote_user = ansible
private_key_file = ~/.ssh/ansible_key
timeout = 30
retry_files_enabled = False
stdout_callback = yaml
gathering = smart
fact_caching = jsonfile
fact_caching_connection = ~/.ansible/facts_cache
fact_caching_timeout = 86400
interpreter_python = auto_silent
deprecation_warnings = True
command_warnings = True

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=3600s -o PreferredAuthentications=publickey
pipelining = True
control_path = ~/.ansible/cp/%%h-%%p-%%r

[privilege_escalation]
become = False
become_method = sudo
become_user = root
become_ask_pass = False
EOF
```

3. **Create Basic Inventory**:
```bash
# Create simple inventory file
mkdir -p ~/ansible-project/inventory
cat > ~/ansible-project/inventory/hosts.yml <<EOF
all:
  children:
    webservers:
      hosts:
        web-01:
          ansible_host: 192.168.1.10
        web-02:
          ansible_host: 192.168.1.11
    databases:
      hosts:
        db-01:
          ansible_host: 192.168.1.20
  vars:
    ansible_user: ansible
    ansible_ssh_private_key_file: ~/.ssh/ansible_key
EOF
```

4. **Verify Target Host Python**:
```bash
# Check Python availability on target hosts
ansible all -i inventory/hosts.yml -m raw -a "python3 --version || python --version"

# Install Python if needed (Ubuntu/Debian example)
ansible all -i inventory/hosts.yml -m raw -a "apt update && apt install -y python3" --become
```

### Testing Initial Setup

```bash
# Test connectivity to all hosts
ansible all -i inventory/hosts.yml -m ping

# Gather facts from all hosts
ansible all -i inventory/hosts.yml -m setup

# Test privilege escalation
ansible all -i inventory/hosts.yml -m command -a "whoami" --become

# Check disk space on all hosts
ansible all -i inventory/hosts.yml -m command -a "df -h"

# Verify SSH keys are working
ansible all -i inventory/hosts.yml -m command -a "uptime"

# Test basic file operations
ansible all -i inventory/hosts.yml -m file -a "path=/tmp/ansible-test state=touch" --become
ansible all -i inventory/hosts.yml -m file -a "path=/tmp/ansible-test state=absent" --become
```

**WARNING:** Ensure SSH key authentication is working and hosts are accessible before proceeding with complex playbooks!

## 5. Service Management

### Ansible Controller Service (systemd)

```bash
# Create Ansible controller service for scheduled playbooks
sudo tee /etc/systemd/system/ansible-controller.service > /dev/null <<EOF
[Unit]
Description=Ansible Controller Service
After=network.target
Wants=network-online.target

[Service]
Type=oneshot
User=ansible
Group=ansible
WorkingDirectory=/opt/ansible
ExecStart=/usr/local/bin/ansible-playbook -i inventories/production playbooks/maintenance.yml
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create timer for regular execution
sudo tee /etc/systemd/system/ansible-controller.timer > /dev/null <<EOF
[Unit]
Description=Run Ansible Controller Service
Requires=ansible-controller.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable ansible-controller.timer
sudo systemctl start ansible-controller.timer

# Check status
sudo systemctl status ansible-controller.timer
```

### Ansible Tower/AWX Service Management

```bash
# AWX service management (Docker-based)
# Start AWX services
sudo docker-compose -f /opt/awx/installer/docker-compose.yml up -d

# Stop AWX services
sudo docker-compose -f /opt/awx/installer/docker-compose.yml down

# Restart AWX services
sudo docker-compose -f /opt/awx/installer/docker-compose.yml restart

# View AWX logs
sudo docker-compose -f /opt/awx/installer/docker-compose.yml logs -f

# Check AWX service status
sudo docker-compose -f /opt/awx/installer/docker-compose.yml ps

# Update AWX
cd /opt/awx
git pull
sudo docker-compose -f installer/docker-compose.yml down
sudo docker-compose -f installer/docker-compose.yml build --no-cache
sudo docker-compose -f installer/docker-compose.yml up -d
```

### Ansible Pull Service (for Pull-based Configuration)

```bash
# Create ansible-pull service for decentralized management
sudo tee /etc/systemd/system/ansible-pull.service > /dev/null <<EOF
[Unit]
Description=Ansible Pull Configuration Management
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/ansible-pull -U https://github.com/company/ansible-config.git -i localhost, local.yml
StandardOutput=journal
StandardError=journal
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF

# Create timer for ansible-pull
sudo tee /etc/systemd/system/ansible-pull.timer > /dev/null <<EOF
[Unit]
Description=Run Ansible Pull every 30 minutes
Requires=ansible-pull.service

[Timer]
OnCalendar=*:0/30
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
EOF

# Enable ansible-pull timer
sudo systemctl daemon-reload
sudo systemctl enable ansible-pull.timer
sudo systemctl start ansible-pull.timer
```

### Cross-Platform Service Management

#### macOS (launchd)

```bash
# Create launchd plist for Ansible automation
sudo tee /Library/LaunchDaemons/com.company.ansible.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.ansible</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ansible-playbook</string>
        <string>-i</string>
        <string>/opt/ansible/inventory/hosts.yml</string>
        <string>/opt/ansible/playbooks/maintenance.yml</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>2</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/ansible.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ansible.error.log</string>
    <key>UserName</key>
    <string>ansible</string>
    <key>WorkingDirectory</key>
    <string>/opt/ansible</string>
</dict>
</plist>
EOF

# Load and start the service
sudo launchctl load /Library/LaunchDaemons/com.company.ansible.plist
sudo launchctl start com.company.ansible
```

#### Windows (Task Scheduler via PowerShell)

```powershell
# Create scheduled task for Ansible in Windows (running in WSL)
$TaskName = "Ansible-Configuration-Management"
$TaskDescription = "Run Ansible playbooks for system configuration"

$Action = New-ScheduledTaskAction -Execute "wsl" -Argument "ansible-playbook -i /home/ansible/inventory/hosts.yml /home/ansible/playbooks/windows-maintenance.yml"

$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"

$Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings

# Start the task
Start-ScheduledTask -TaskName $TaskName

# Check task status
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
```

## Project Structure and Configuration

### Professional Project Structure
```bash
# Create comprehensive Ansible project structure
mkdir -p ~/ansible-infrastructure/{
  inventories/{production,staging,development},
  playbooks,
  roles,
  group_vars,
  host_vars,
  library,
  filter_plugins,
  callback_plugins,
  vault,
  collections,
  logs
}

cd ~/ansible-infrastructure

# Create ansible.cfg with security best practices
cat > ansible.cfg <<EOF
[defaults]
inventory = inventories/production/hosts.yml
remote_user = ansible
private_key_file = ~/.ssh/ansible_key
host_key_checking = True
timeout = 30
retry_files_enabled = False
stdout_callback = yaml
bin_ansible_callbacks = True
gathering = smart
fact_caching = jsonfile
fact_caching_connection = ~/.ansible/facts_cache
fact_caching_timeout = 86400
interpreter_python = auto_silent
vault_password_file = ~/.ansible_vault_pass

# Logging
log_path = logs/ansible.log
display_skipped_hosts = False
display_ok_hosts = False

# Performance
forks = 20
poll_interval = 15
internal_poll_interval = 0.001

# Security
command_warnings = True
deprecation_warnings = True
action_warnings = True
localhost_warning = True

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=3600s -o PreferredAuthentications=publickey
pipelining = True
control_path = ~/.ansible/cp/%%h-%%p-%%r
retries = 3

[privilege_escalation]
become = False
become_method = sudo
become_user = root
become_ask_pass = False

[inventory]
enable_plugins = host_list, script, auto, yaml, ini, toml
cache = True
cache_plugin = jsonfile
cache_timeout = 3600
cache_connection = ~/.ansible/inventory_cache

[galaxy]
server_list = automation_hub, galaxy
EOF
```

### Advanced Inventory Management
```bash
# Create production inventory with groups and variables
cat > inventories/production/hosts.yml <<EOF
all:
  children:
    webservers:
      hosts:
        web-prod-01:
          ansible_host: 10.0.1.10
          ansible_user: ansible
          server_role: frontend
          backup_enabled: true
        web-prod-02:
          ansible_host: 10.0.1.11
          ansible_user: ansible
          server_role: frontend
          backup_enabled: true
        web-prod-03:
          ansible_host: 10.0.1.12
          ansible_user: ansible
          server_role: frontend
          backup_enabled: true
      vars:
        http_port: 80
        https_port: 443
        max_clients: 200
        environment: production
        monitoring_enabled: true

    dbservers:
      hosts:
        db-prod-01:
          ansible_host: 10.0.2.10
          ansible_user: ansible
          mysql_server_id: 1
          mysql_role: master
        db-prod-02:
          ansible_host: 10.0.2.11
          ansible_user: ansible
          mysql_server_id: 2
          mysql_role: slave
      vars:
        mysql_port: 3306
        mysql_root_password: "{{ vault_mysql_root_password }}"
        mysql_replication_user: "{{ vault_mysql_replication_user }}"
        mysql_replication_password: "{{ vault_mysql_replication_password }}"

    loadbalancers:
      hosts:
        lb-prod-01:
          ansible_host: 10.0.3.10
          ansible_user: ansible
          lb_algorithm: roundrobin
        lb-prod-02:
          ansible_host: 10.0.3.11
          ansible_user: ansible
          lb_algorithm: roundrobin
      vars:
        haproxy_stats_enabled: true
        haproxy_stats_user: admin
        haproxy_stats_password: "{{ vault_haproxy_stats_password }}"

    monitoring:
      hosts:
        monitor-prod-01:
          ansible_host: 10.0.4.10
          ansible_user: ansible
          prometheus_retention: 30d
          grafana_admin_password: "{{ vault_grafana_admin_password }}"

    bastion:
      hosts:
        bastion-prod-01:
          ansible_host: bastion.example.com
          ansible_user: ansible
          ansible_port: 22

# Global variables for all hosts
webservers:
  vars:
    nginx_worker_processes: auto
    nginx_worker_connections: 1024
    ssl_certificate_path: /etc/ssl/certs
    backup_schedule: "0 2 * * *"

dbservers:
  vars:
    mysql_innodb_buffer_pool_size: 2G
    mysql_max_connections: 200
    backup_schedule: "0 1 * * *"
    monitoring_enabled: true
EOF

# Create dynamic inventory script for cloud environments
cat > inventories/production/aws_ec2.yml <<EOF
plugin: amazon.aws.aws_ec2
regions:
  - us-west-2
  - us-east-1
filters:
  tag:Environment: production
  tag:Ansible: managed
  instance-state-name: running

hostnames:
  - tag:Name
  - dns-name
  - private-ip-address

compose:
  ansible_host: private_ip_address
  ec2_state: ec2_state_name
  ec2_arch: ec2_architecture

groups:
  # Group by instance type
  webservers: "'web' in tags.Role"
  databases: "'db' in tags.Role"
  loadbalancers: "'lb' in tags.Role"
  
  # Group by environment
  production: "tags.Environment == 'production'"
  staging: "tags.Environment == 'staging'"
  
  # Group by availability zone
  us_west_2a: ec2_placement_availability_zone == "us-west-2a"
  us_west_2b: ec2_placement_availability_zone == "us-west-2b"

keyed_groups:
  # Create groups based on tags
  - key: tags.Environment
    prefix: env
  - key: tags.Role  
    prefix: role
  - key: ec2_instance_type
    prefix: type
EOF
```

### Ansible Vault Security
```bash
# Create strong vault password
openssl rand -base64 32 > ~/.ansible_vault_pass
chmod 600 ~/.ansible_vault_pass

# Create encrypted vault file for secrets
ansible-vault create group_vars/all/vault.yml
# Enter secure passwords and API keys:
# vault_mysql_root_password: your_secure_mysql_password
# vault_grafana_admin_password: your_secure_grafana_password  
# vault_ssl_private_key: |
#   -----BEGIN PRIVATE KEY-----
#   your_private_key_content
#   -----END PRIVATE KEY-----

# Create non-encrypted variables file
cat > group_vars/all/vars.yml <<EOF
# Non-sensitive variables
mysql_port: 3306
nginx_port: 80
grafana_port: 3000
prometheus_port: 9090

# Reference vault variables
mysql_root_password: "{{ vault_mysql_root_password }}"
grafana_admin_password: "{{ vault_grafana_admin_password }}"

# SSL configuration
ssl_certificate_path: /etc/ssl/certs/server.crt
ssl_private_key_path: /etc/ssl/private/server.key
ssl_private_key_content: "{{ vault_ssl_private_key }}"

# Security settings
ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile=~/.ssh/known_hosts'
ansible_become_method: sudo
ansible_become_user: root
EOF

# Edit vault file
ansible-vault edit group_vars/all/vault.yml

# View vault file (read-only)
ansible-vault view group_vars/all/vault.yml

# Change vault password
ansible-vault rekey group_vars/all/vault.yml
```

## Comprehensive Playbooks

### System Hardening Playbook
```bash
cat > playbooks/system-hardening.yml <<EOF
---
- name: System Security Hardening
  hosts: all
  become: yes
  gather_facts: yes
  vars:
    security_packages:
      - fail2ban
      - ufw
      - aide
      - chkrootkit
      - rkhunter
      - clamav
      - lynis
    
    disabled_services:
      - telnet
      - rsh
      - rlogin
      - tftp
      - talk
      - finger

  pre_tasks:
    - name: Update package cache
      package:
        update_cache: yes
        cache_valid_time: 3600
      when: ansible_os_family in ["Debian", "RedHat"]

  tasks:
    # System updates
    - name: Upgrade all packages
      package:
        name: "*"
        state: latest
      when: ansible_os_family == "RedHat"

    - name: Upgrade all packages (Debian/Ubuntu)
      apt:
        upgrade: dist
        autoremove: yes
        autoclean: yes
      when: ansible_os_family == "Debian"

    # Install security packages
    - name: Install security packages
      package:
        name: "{{ security_packages }}"
        state: present

    # User security
    - name: Create ansible user with limited privileges
      user:
        name: ansible
        groups: sudo
        shell: /bin/bash
        create_home: yes
        generate_ssh_key: yes
        ssh_key_bits: 4096
        ssh_key_type: rsa

    - name: Configure sudo for ansible user
      lineinfile:
        path: /etc/sudoers.d/ansible
        line: 'ansible ALL=(ALL) NOPASSWD:ALL'
        create: yes
        mode: '0440'
        validate: 'visudo -cf %s'

    # SSH hardening
    - name: Configure SSH security
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        backup: yes
      loop:
        - { regexp: '^#?PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^#?PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^#?X11Forwarding', line: 'X11Forwarding no' }
        - { regexp: '^#?MaxAuthTries', line: 'MaxAuthTries 3' }
        - { regexp: '^#?ClientAliveInterval', line: 'ClientAliveInterval 300' }
        - { regexp: '^#?ClientAliveCountMax', line: 'ClientAliveCountMax 0' }
        - { regexp: '^#?Protocol', line: 'Protocol 2' }
        - { regexp: '^#?LogLevel', line: 'LogLevel VERBOSE' }
      notify: restart ssh

    # Firewall configuration
    - name: Configure UFW firewall (Debian/Ubuntu)
      ufw:
        state: enabled
        policy: deny
        direction: incoming
      when: ansible_os_family == "Debian"

    - name: Allow SSH through UFW
      ufw:
        rule: allow
        port: 22
        proto: tcp
        comment: 'SSH access'
      when: ansible_os_family == "Debian"

    - name: Configure firewalld (RHEL/CentOS/Fedora)
      firewalld:
        state: enabled
        permanent: yes
        immediate: yes
      when: ansible_os_family == "RedHat"

    - name: Allow SSH through firewalld
      firewalld:
        service: ssh
        permanent: yes
        state: enabled
        immediate: yes
      when: ansible_os_family == "RedHat"

    # Disable unnecessary services
    - name: Disable unnecessary services
      systemd:
        name: "{{ item }}"
        enabled: no
        state: stopped
      loop: "{{ disabled_services }}"
      ignore_errors: yes

    # File system security
    - name: Set proper permissions on sensitive files
      file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
        owner: root
        group: root
      loop:
        - { path: '/etc/passwd', mode: '0644' }
        - { path: '/etc/shadow', mode: '0640' }
        - { path: '/etc/group', mode: '0644' }
        - { path: '/etc/gshadow', mode: '0640' }
        - { path: '/etc/ssh/sshd_config', mode: '0600' }

    # Kernel security parameters
    - name: Configure kernel security parameters
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        sysctl_set: yes
        state: present
        reload: yes
      loop:
        - { key: 'net.ipv4.ip_forward', value: '0' }
        - { key: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.accept_source_route', value: '0' }
        - { key: 'net.ipv4.conf.default.accept_source_route', value: '0' }
        - { key: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.secure_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.secure_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { key: 'net.ipv4.conf.default.log_martians', value: '1' }
        - { key: 'kernel.randomize_va_space', value: '2' }

    # Configure fail2ban
    - name: Configure fail2ban for SSH protection
      template:
        src: templates/fail2ban-jail.local.j2
        dest: /etc/fail2ban/jail.local
        backup: yes
      notify: restart fail2ban

  handlers:
    - name: restart ssh
      service:
        name: "{{ 'ssh' if ansible_os_family == 'Debian' else 'sshd' }}"
        state: restarted

    - name: restart fail2ban
      service:
        name: fail2ban
        state: restarted
EOF
```

### Application Deployment Playbook
```bash
cat > playbooks/web-application-deployment.yml <<EOF
---
- name: Deploy Web Application Stack
  hosts: webservers
  become: yes
  serial: "25%"  # Rolling deployment
  max_fail_percentage: 10
  vars:
    app_name: mywebapp
    app_version: "{{ app_version | default('latest') }}"
    app_port: 3000
    nginx_workers: "{{ ansible_processor_cores }}"
    
  pre_tasks:
    - name: Check if maintenance mode file exists
      stat:
        path: /var/www/html/maintenance.html
      register: maintenance_mode

    - name: Fail if in maintenance mode
      fail:
        msg: "Server is in maintenance mode"
      when: maintenance_mode.stat.exists and not force_deployment | default(false)

  tasks:
    # Application deployment
    - name: Create application user
      user:
        name: "{{ app_name }}"
        system: yes
        shell: /bin/false
        home: "/opt/{{ app_name }}"
        create_home: yes

    - name: Create application directories
      file:
        path: "{{ item }}"
        state: directory
        owner: "{{ app_name }}"
        group: "{{ app_name }}"
        mode: '0755'
      loop:
        - "/opt/{{ app_name }}"
        - "/opt/{{ app_name }}/releases"
        - "/opt/{{ app_name }}/shared"
        - "/var/log/{{ app_name }}"

    - name: Download application release
      get_url:
        url: "https://releases.example.com/{{ app_name }}/{{ app_version }}/{{ app_name }}-{{ app_version }}.tar.gz"
        dest: "/tmp/{{ app_name }}-{{ app_version }}.tar.gz"
        mode: '0644'
        timeout: 300
      register: download_result

    - name: Extract application
      unarchive:
        src: "/tmp/{{ app_name }}-{{ app_version }}.tar.gz"
        dest: "/opt/{{ app_name }}/releases/"
        owner: "{{ app_name }}"
        group: "{{ app_name }}"
        remote_src: yes
        creates: "/opt/{{ app_name }}/releases/{{ app_version }}"

    - name: Create symlink to current release
      file:
        src: "/opt/{{ app_name }}/releases/{{ app_version }}"
        dest: "/opt/{{ app_name }}/current"
        state: link
        owner: "{{ app_name }}"
        group: "{{ app_name }}"
      notify:
        - reload application
        - reload nginx

    # Configuration management
    - name: Deploy application configuration
      template:
        src: "templates/{{ app_name }}.conf.j2"
        dest: "/opt/{{ app_name }}/shared/{{ app_name }}.conf"
        owner: "{{ app_name }}"
        group: "{{ app_name }}"
        mode: '0640'
        backup: yes
      notify: reload application

    # Service management
    - name: Deploy systemd service file
      template:
        src: "templates/{{ app_name }}.service.j2"
        dest: "/etc/systemd/system/{{ app_name }}.service"
        mode: '0644'
      notify:
        - daemon reload
        - restart application

    - name: Enable and start application service
      systemd:
        name: "{{ app_name }}"
        enabled: yes
        state: started
        daemon_reload: yes

    # Health check
    - name: Wait for application to be ready
      uri:
        url: "http://localhost:{{ app_port }}/health"
        method: GET
        status_code: 200
      retries: 30
      delay: 10

    # Cleanup old releases
    - name: Clean up old releases (keep last 3)
      shell: |
        cd /opt/{{ app_name }}/releases
        ls -t | tail -n +4 | xargs rm -rf
      args:
        executable: /bin/bash

  post_tasks:
    - name: Verify application is running
      uri:
        url: "http://{{ ansible_default_ipv4.address }}:{{ app_port }}/health"
        method: GET
        status_code: 200
      delegate_to: localhost

    - name: Log deployment success
      lineinfile:
        path: "/var/log/{{ app_name }}/deployments.log"
        line: "{{ ansible_date_time.iso8601 }} - Successfully deployed {{ app_version }} to {{ inventory_hostname }}"
        create: yes

  handlers:
    - name: daemon reload
      systemd:
        daemon_reload: yes

    - name: restart application
      systemd:
        name: "{{ app_name }}"
        state: restarted

    - name: reload application
      systemd:
        name: "{{ app_name }}"
        state: reloaded

    - name: reload nginx
      service:
        name: nginx
        state: reloaded
EOF
```

### Infrastructure as Code Playbook
```bash
cat > playbooks/infrastructure-provisioning.yml <<EOF
---
- name: Infrastructure Provisioning and Configuration
  hosts: all
  become: yes
  strategy: free  # Parallel execution
  vars:
    base_packages:
      Debian:
        - curl
        - wget
        - vim
        - htop
        - git
        - python3
        - python3-pip
        - unzip
        - tree
      RedHat:
        - curl
        - wget
        - vim
        - htop
        - git
        - python3
        - python3-pip
        - unzip
        - tree
        - epel-release

  tasks:
    # System preparation
    - name: Set hostname
      hostname:
        name: "{{ inventory_hostname }}"

    - name: Update /etc/hosts
      lineinfile:
        path: /etc/hosts
        line: "{{ ansible_default_ipv4.address }} {{ inventory_hostname }}"
        backup: yes

    # Package management
    - name: Install base packages
      package:
        name: "{{ base_packages[ansible_os_family] | default(base_packages['Debian']) }}"
        state: present

    # Time synchronization
    - name: Install and configure NTP
      package:
        name: "{{ 'ntp' if ansible_os_family == 'Debian' else 'chrony' }}"
        state: present

    - name: Start and enable time synchronization
      service:
        name: "{{ 'ntp' if ansible_os_family == 'Debian' else 'chronyd' }}"
        state: started
        enabled: yes

    # Log management
    - name: Configure logrotate for application logs
      template:
        src: templates/app-logrotate.j2
        dest: /etc/logrotate.d/applications
        mode: '0644'

    # Monitoring agent installation
    - name: Install Node Exporter for Prometheus monitoring
      get_url:
        url: "https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz"
        dest: /tmp/node_exporter.tar.gz
        mode: '0644'

    - name: Extract Node Exporter
      unarchive:
        src: /tmp/node_exporter.tar.gz
        dest: /tmp
        remote_src: yes

    - name: Copy Node Exporter binary
      copy:
        src: /tmp/node_exporter-1.6.1.linux-amd64/node_exporter
        dest: /usr/local/bin/node_exporter
        mode: '0755'
        owner: root
        group: root
        remote_src: yes

    - name: Create node_exporter systemd service
      template:
        src: templates/node_exporter.service.j2
        dest: /etc/systemd/system/node_exporter.service
        mode: '0644'
      notify:
        - daemon reload
        - restart node_exporter

    # Security configuration
    - name: Configure kernel parameters for security
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        sysctl_set: yes
        state: present
        reload: yes
      loop:
        - { key: 'kernel.dmesg_restrict', value: '1' }
        - { key: 'kernel.kptr_restrict', value: '2' }
        - { key: 'kernel.yama.ptrace_scope', value: '1' }
        - { key: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { key: 'net.ipv4.conf.default.log_martians', value: '1' }
        - { key: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.send_redirects', value: '0' }

    # File integrity monitoring
    - name: Initialize AIDE database
      shell: |
        aide --init
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      args:
        creates: /var/lib/aide/aide.db

    - name: Schedule AIDE integrity checks
      cron:
        name: "AIDE integrity check"
        minute: "0"
        hour: "3"
        job: "/usr/bin/aide --check"
        user: root

  handlers:
    - name: daemon reload
      systemd:
        daemon_reload: yes

    - name: restart node_exporter
      service:
        name: node_exporter
        state: restarted
        enabled: yes
EOF
```

## Advanced Role Development

### Comprehensive NGINX Role
```bash
# Create NGINX role structure
ansible-galaxy init roles/nginx

# Main tasks
cat > roles/nginx/tasks/main.yml <<EOF
---
# NGINX Installation and Configuration Role
- name: Include OS-specific variables
  include_vars: "{{ ansible_os_family }}.yml"

- name: Install NGINX
  include_tasks: "install-{{ ansible_os_family }}.yml"

- name: Create NGINX directories
  file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: '0755'
  loop:
    - /etc/nginx/sites-available
    - /etc/nginx/sites-enabled
    - /etc/nginx/conf.d
    - /var/log/nginx
    - /var/cache/nginx

- name: Generate DH parameters
  openssl_dhparam:
    path: /etc/ssl/certs/dhparam.pem
    size: 2048
  when: nginx_ssl_enabled | default(false)

- name: Deploy NGINX main configuration
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    backup: yes
    validate: 'nginx -t -c %s'
  notify: reload nginx

- name: Deploy virtual host configurations
  template:
    src: vhost.conf.j2
    dest: "/etc/nginx/sites-available/{{ item.name }}.conf"
    backup: yes
  loop: "{{ nginx_vhosts | default([]) }}"
  notify: reload nginx

- name: Enable virtual hosts
  file:
    src: "/etc/nginx/sites-available/{{ item.name }}.conf"
    dest: "/etc/nginx/sites-enabled/{{ item.name }}.conf"
    state: link
  loop: "{{ nginx_vhosts | default([]) }}"
  when: item.enabled | default(true)
  notify: reload nginx

- name: Remove default site
  file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  notify: reload nginx

- name: Start and enable NGINX
  service:
    name: nginx
    state: started
    enabled: yes

- name: Configure log rotation
  template:
    src: nginx-logrotate.j2
    dest: /etc/logrotate.d/nginx
    mode: '0644'

- name: Setup NGINX monitoring
  include_tasks: monitoring.yml
  when: nginx_monitoring_enabled | default(false)

- name: Configure SSL certificates
  include_tasks: ssl.yml
  when: nginx_ssl_enabled | default(false)
EOF

# OS-specific installation tasks
cat > roles/nginx/tasks/install-Debian.yml <<EOF
---
- name: Add NGINX signing key (Debian/Ubuntu)
  apt_key:
    url: https://nginx.org/keys/nginx_signing.key
    state: present

- name: Add NGINX repository (Debian/Ubuntu)
  apt_repository:
    repo: "deb https://nginx.org/packages/{{ ansible_distribution | lower }}/ {{ ansible_distribution_release }} nginx"
    state: present

- name: Install NGINX (Debian/Ubuntu)
  apt:
    name: nginx
    state: present
    update_cache: yes
EOF

cat > roles/nginx/tasks/install-RedHat.yml <<EOF
---
- name: Add NGINX repository (RHEL/CentOS)
  yum_repository:
    name: nginx
    description: NGINX Repository
    baseurl: "https://nginx.org/packages/centos/{{ ansible_distribution_major_version }}/$basearch/"
    gpgcheck: yes
    gpgkey: https://nginx.org/keys/nginx_signing.key
    enabled: yes

- name: Install NGINX (RHEL/CentOS)
  yum:
    name: nginx
    state: present
EOF

# Variables
cat > roles/nginx/vars/main.yml <<EOF
---
nginx_user: nginx
nginx_worker_processes: auto
nginx_worker_connections: 1024
nginx_keepalive_timeout: 65
nginx_ssl_enabled: false
nginx_monitoring_enabled: true

nginx_security_headers:
  - "add_header X-Frame-Options SAMEORIGIN always;"
  - "add_header X-Content-Type-Options nosniff always;"
  - "add_header X-XSS-Protection '1; mode=block' always;"
  - "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"

nginx_default_vhost:
  name: default
  listen: 80
  server_name: "_"
  root: /var/www/html
  index: index.html
  enabled: false
EOF

# Templates
cat > roles/nginx/templates/nginx.conf.j2 <<EOF
user {{ nginx_user }};
worker_processes {{ nginx_worker_processes }};
pid /var/run/nginx.pid;

events {
    worker_connections {{ nginx_worker_connections }};
    use epoll;
    multi_accept on;
}

http {
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout {{ nginx_keepalive_timeout }};
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL configuration
{% if nginx_ssl_enabled %}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
{% endif %}

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        application/javascript
        application/json
        application/xml
        text/css
        text/javascript
        text/xml
        text/plain;

    # Security headers
{% for header in nginx_security_headers %}
    {{ header }}
{% endfor %}

    # Logging
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=login:10m rate=10r/m;
    limit_conn_zone \$binary_remote_addr zone=addr:10m;

    # Include configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Handlers
cat > roles/nginx/handlers/main.yml <<EOF
---
- name: restart nginx
  service:
    name: nginx
    state: restarted

- name: reload nginx
  service:
    name: nginx
    state: reloaded

- name: validate nginx config
  command: nginx -t
  changed_when: false
EOF
```

## Security and Compliance

### Ansible Security Scanner Integration
```bash
# Create security scanning playbook
cat > playbooks/security-scan.yml <<EOF
---
- name: Security Compliance Scanning
  hosts: all
  become: yes
  gather_facts: yes
  vars:
    scan_results_dir: "/tmp/security-scans"
    
  tasks:
    - name: Create scan results directory
      file:
        path: "{{ scan_results_dir }}"
        state: directory
        mode: '0755'

    # CIS benchmark scanning
    - name: Download CIS benchmark script
      get_url:
        url: "https://github.com/dev-sec/cis-dil-benchmark/archive/master.zip"
        dest: "/tmp/cis-benchmark.zip"
        mode: '0644'

    - name: Run CIS benchmark scan
      shell: |
        cd /tmp
        unzip -o cis-benchmark.zip
        cd cis-dil-benchmark-master
        bash cis_ubuntu2204.sh > {{ scan_results_dir }}/cis-scan-{{ inventory_hostname }}.txt
      args:
        creates: "{{ scan_results_dir }}/cis-scan-{{ inventory_hostname }}.txt"

    # Lynis security audit
    - name: Install Lynis
      package:
        name: lynis
        state: present

    - name: Run Lynis security audit
      command: lynis audit system --quiet --cronjob
      register: lynis_result
      changed_when: false

    - name: Save Lynis results
      copy:
        content: "{{ lynis_result.stdout }}"
        dest: "{{ scan_results_dir }}/lynis-scan-{{ inventory_hostname }}.txt"
        mode: '0644'

    # OpenSCAP compliance scanning
    - name: Install OpenSCAP (RHEL/CentOS)
      package:
        name:
          - openscap-scanner
          - scap-security-guide
        state: present
      when: ansible_os_family == "RedHat"

    - name: Install OpenSCAP (Debian/Ubuntu)
      package:
        name:
          - libopenscap8
          - ssg-debian
        state: present
      when: ansible_os_family == "Debian"

    - name: Run OpenSCAP scan
      shell: |
        oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard \
          --results {{ scan_results_dir }}/oscap-results-{{ inventory_hostname }}.xml \
          --report {{ scan_results_dir }}/oscap-report-{{ inventory_hostname }}.html \
          /usr/share/xml/scap/ssg/content/ssg-{{ ansible_distribution | lower }}{{ ansible_distribution_major_version }}-xccdf.xml
      ignore_errors: yes
      when: ansible_os_family in ["RedHat", "Debian"]

    # Vulnerability scanning with Trivy
    - name: Install Trivy vulnerability scanner
      shell: |
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
      args:
        creates: /usr/local/bin/trivy

    - name: Run Trivy filesystem scan
      shell: |
        trivy fs --format json --output {{ scan_results_dir }}/trivy-scan-{{ inventory_hostname }}.json /
      ignore_errors: yes

    # Collect scan results
    - name: Fetch scan results to control machine
      fetch:
        src: "{{ item }}"
        dest: "./security-reports/{{ inventory_hostname }}/"
        flat: yes
      loop:
        - "{{ scan_results_dir }}/cis-scan-{{ inventory_hostname }}.txt"
        - "{{ scan_results_dir }}/lynis-scan-{{ inventory_hostname }}.txt"
        - "{{ scan_results_dir }}/oscap-report-{{ inventory_hostname }}.html"
        - "{{ scan_results_dir }}/trivy-scan-{{ inventory_hostname }}.json"
      ignore_errors: yes
      delegate_to: localhost

  post_tasks:
    - name: Generate compliance summary
      template:
        src: templates/compliance-summary.j2
        dest: "{{ scan_results_dir }}/compliance-summary-{{ inventory_hostname }}.txt"
        mode: '0644'
EOF
```

### Ansible AWX/Tower Integration
```bash
# Install Ansible AWX (open source)
cat > playbooks/install-awx.yml <<EOF
---
- name: Install Ansible AWX
  hosts: localhost
  connection: local
  become: yes
  vars:
    awx_namespace: awx
    awx_admin_user: admin
    awx_admin_password: "{{ vault_awx_admin_password }}"

  tasks:
    - name: Install prerequisite packages
      package:
        name:
          - git
          - curl
          - docker.io
          - docker-compose
        state: present

    - name: Clone AWX repository
      git:
        repo: https://github.com/ansible/awx.git
        dest: /opt/awx
        version: devel

    - name: Create AWX Docker inventory
      template:
        src: templates/awx-docker-inventory.j2
        dest: /opt/awx/installer/inventory
        mode: '0644'

    - name: Install AWX using Ansible
      shell: ansible-playbook -i inventory install.yml
      args:
        chdir: /opt/awx/installer
      environment:
        ANSIBLE_HOST_KEY_CHECKING: False

    - name: Wait for AWX to be ready
      uri:
        url: "http://localhost:80/api/v2/ping/"
        method: GET
      retries: 30
      delay: 10

    - name: Configure AWX organizations and projects
      uri:
        url: "http://localhost:80/api/v2/organizations/"
        method: POST
        user: "{{ awx_admin_user }}"
        password: "{{ awx_admin_password }}"
        force_basic_auth: yes
        body_format: json
        body:
          name: "Production"
          description: "Production environment organization"
        status_code: [200, 201, 409]
EOF
```

## Multi-Cloud Automation

### AWS Infrastructure Automation
```bash
cat > playbooks/aws-infrastructure.yml <<EOF
---
- name: AWS Infrastructure Automation
  hosts: localhost
  connection: local
  gather_facts: no
  vars:
    aws_region: "{{ aws_region | default('us-west-2') }}"
    vpc_cidr: "{{ vpc_cidr | default('10.0.0.0/16') }}"
    environment: "{{ environment | default('production') }}"

  tasks:
    # VPC Creation
    - name: Create VPC
      amazon.aws.ec2_vpc_info:
        filters:
          "tag:Name": "{{ environment }}-vpc"
        region: "{{ aws_region }}"
      register: existing_vpc

    - name: Create new VPC if not exists
      amazon.aws.ec2_vpc_net:
        name: "{{ environment }}-vpc"
        cidr_block: "{{ vpc_cidr }}"
        region: "{{ aws_region }}"
        state: present
        dns_hostnames: yes
        dns_support: yes
        tags:
          Environment: "{{ environment }}"
          ManagedBy: ansible
      register: vpc
      when: existing_vpc.vpcs | length == 0

    # Security Groups
    - name: Create web security group
      amazon.aws.ec2_group:
        name: "{{ environment }}-web-sg"
        description: "Security group for web servers"
        vpc_id: "{{ vpc.vpc.id if vpc.vpc is defined else existing_vpc.vpcs[0].vpc_id }}"
        region: "{{ aws_region }}"
        rules:
          - proto: tcp
            ports:
              - 80
              - 443
            cidr_ip: 0.0.0.0/0
            rule_desc: "HTTP and HTTPS access"
          - proto: tcp
            ports:
              - 22
            group_id: "{{ environment }}-bastion-sg"
            rule_desc: "SSH from bastion"
        tags:
          Environment: "{{ environment }}"

    # Launch EC2 instances
    - name: Launch web servers
      amazon.aws.ec2_instance:
        name: "{{ environment }}-web-{{ item }}"
        instance_type: t3.medium
        image_id: ami-0c02fb55956c7d316  # Amazon Linux 2
        key_name: "{{ ec2_key_name }}"
        vpc_subnet_id: "{{ web_subnet_id }}"
        security_groups:
          - "{{ environment }}-web-sg"
        region: "{{ aws_region }}"
        state: running
        wait: yes
        wait_timeout: 300
        user_data: |
          #!/bin/bash
          yum update -y
          yum install -y python3
        tags:
          Environment: "{{ environment }}"
          Role: webserver
          Ansible: managed
      loop: "{{ range(1, web_server_count + 1) | list }}"
      register: web_instances

    # Add instances to inventory
    - name: Add web servers to inventory
      add_host:
        name: "{{ item.instances[0].tags.Name }}"
        hostname: "{{ item.instances[0].public_ip_address }}"
        groups: webservers
        ansible_ssh_private_key_file: "~/.ssh/{{ ec2_key_name }}.pem"
        ansible_user: ec2-user
      loop: "{{ web_instances.results }}"
      changed_when: false
EOF
```

### Kubernetes Cluster Management
```bash
cat > playbooks/k8s-cluster-management.yml <<EOF
---
- name: Kubernetes Cluster Management with Ansible
  hosts: k8s_masters
  become: yes
  serial: 1
  vars:
    k8s_version: "1.28.2"
    containerd_version: "1.6.24"
    cni_version: "1.3.0"

  tasks:
    # Pre-flight checks
    - name: Check system requirements
      assert:
        that:
          - ansible_memtotal_mb >= 1700
          - ansible_processor_cores >= 2
        fail_msg: "System doesn't meet minimum requirements"

    - name: Verify connectivity to all nodes
      ping:
      delegate_to: "{{ item }}"
      loop: "{{ groups['k8s_all'] }}"

    # Container runtime setup
    - name: Install containerd
      include_role:
        name: containerd
      vars:
        containerd_version: "{{ containerd_version }}"

    # Kubernetes installation
    - name: Install Kubernetes components
      include_role:
        name: kubernetes
      vars:
        kubernetes_version: "{{ k8s_version }}"

    # Cluster initialization
    - name: Initialize Kubernetes cluster
      shell: |
        kubeadm init \
          --pod-network-cidr=10.244.0.0/16 \
          --service-cidr=10.96.0.0/12 \
          --apiserver-advertise-address={{ ansible_default_ipv4.address }} \
          --node-name={{ inventory_hostname }}
      args:
        creates: /etc/kubernetes/admin.conf
      register: kubeadm_init

    - name: Create .kube directory
      file:
        path: "{{ ansible_env.HOME }}/.kube"
        state: directory
        mode: '0755'

    - name: Copy admin.conf to user's kube config
      copy:
        src: /etc/kubernetes/admin.conf
        dest: "{{ ansible_env.HOME }}/.kube/config"
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
        mode: '0644'
        remote_src: yes

    # Network plugin installation
    - name: Install Flannel CNI
      shell: kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
      environment:
        KUBECONFIG: "{{ ansible_env.HOME }}/.kube/config"

    # Join worker nodes
    - name: Get join command
      shell: kubeadm token create --print-join-command
      register: join_command
      when: inventory_hostname in groups['k8s_masters'][0]

    - name: Join worker nodes to cluster
      shell: "{{ hostvars[groups['k8s_masters'][0]]['join_command'].stdout }}"
      when: inventory_hostname in groups['k8s_workers']

  post_tasks:
    - name: Verify cluster status
      shell: kubectl get nodes
      environment:
        KUBECONFIG: "{{ ansible_env.HOME }}/.kube/config"
      register: cluster_status
      when: inventory_hostname in groups['k8s_masters'][0]

    - name: Display cluster status
      debug:
        var: cluster_status.stdout_lines
      when: inventory_hostname in groups['k8s_masters'][0]
EOF
```

## Performance Optimization

### System-Level Tuning

```bash
# Optimize control machine for Ansible performance
# Kernel parameters for network performance
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# Ansible performance optimization
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
fs.file-max = 100000
EOF

sudo sysctl -p

# Set resource limits for Ansible user
sudo tee -a /etc/security/limits.conf > /dev/null <<EOF
ansible soft nofile 65536
ansible hard nofile 65536
ansible soft nproc 32768
ansible hard nproc 32768
EOF

# SSH client optimization
mkdir -p ~/.ssh
cat >> ~/.ssh/config <<EOF
Host *
    ControlMaster auto
    ControlPersist 3600
    ControlPath ~/.ssh/sockets/%r@%h-%p
    Compression yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive yes
    ConnectTimeout 10
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/known_hosts
EOF

mkdir -p ~/.ssh/sockets
```

### Ansible Performance Configuration

```bash
# High-performance ansible.cfg
cat > ansible-performance.cfg <<EOF
[defaults]
# Core performance settings
forks = 50
poll_interval = 1
internal_poll_interval = 0.001
timeout = 30
host_key_checking = True
gather_timeout = 30
gathering = smart
fact_caching = redis
fact_caching_connection = localhost:6379:0
fact_caching_timeout = 86400
cache_plugins = memory

# Callback and display optimization
stdout_callback = yaml
callbacks_enabled = timer, profile_tasks, profile_roles
display_skipped_hosts = False
display_ok_hosts = False
display_failed_stderr = True

# SSH optimization
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=3600s -o PreferredAuthentications=publickey -o Compression=yes
pipelining = True
control_path = ~/.ansible/sockets/%%h-%%p-%%r
retries = 3
ssh_executable = /usr/bin/ssh

# Connection persistence
[persistent_connection]
connect_timeout = 30
connect_retry_timeout = 15
command_timeout = 30

# Privilege escalation optimization
[privilege_escalation]
become_plugins = sudo, su, pbrun, pfexec, doas, dzdo, ksu, runas, machinectl
become_allow_same_user = False
become_ask_pass = False
EOF

# Use Redis for fact caching (install Redis first)
sudo apt install -y redis-server  # or relevant package manager
pip install redis

# Create performance monitoring script
cat > ansible-performance-monitor.sh <<'EOF'
#!/bin/bash
# Monitor Ansible performance metrics

PLAYBOOK="$1"
if [ -z "$PLAYBOOK" ]; then
    echo "Usage: $0 <playbook>"
    exit 1
fi

# Enable profiling
export ANSIBLE_CALLBACK_PLUGINS="~/.ansible/plugins/callback"
export ANSIBLE_CALLBACKS_ENABLED="timer,profile_tasks,profile_roles"

# Monitor system resources during playbook execution
(
    while pgrep -f ansible-playbook > /dev/null; do
        echo "$(date): CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}'), Memory: $(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
        sleep 5
    done
) &

# Run playbook with timing
time ansible-playbook "$PLAYBOOK" --diff

# Kill monitoring
pkill -P $$
EOF

chmod +x ansible-performance-monitor.sh
```

### Parallel Execution Strategies
```bash
# Create high-performance playbook configuration
cat > playbooks/high-performance-deployment.yml <<EOF
---
- name: High-Performance Deployment
  hosts: all
  become: yes
  strategy: free  # Parallel execution
  serial: "30%"   # Process 30% of hosts at a time
  max_fail_percentage: 10
  gather_facts: yes
  fact_caching: smart
  vars:
    deployment_batch_size: 10
    max_concurrent_tasks: 50

  pre_tasks:
    - name: Check system load
      shell: uptime | awk '{print $(NF-2)}' | sed 's/,//'
      register: system_load
      changed_when: false

    - name: Skip high-load systems
      meta: end_host
      when: system_load.stdout | float > 5.0

  tasks:
    - name: Update packages with retries
      package:
        name: "*"
        state: latest
      retries: 3
      delay: 30
      async: 300
      poll: 10

    - name: Deploy configuration files in parallel
      template:
        src: "{{ item.src }}"
        dest: "{{ item.dest }}"
        mode: "{{ item.mode | default('0644') }}"
        backup: yes
      loop:
        - { src: "nginx.conf.j2", dest: "/etc/nginx/nginx.conf" }
        - { src: "mysql.cnf.j2", dest: "/etc/mysql/my.cnf" }
        - { src: "redis.conf.j2", dest: "/etc/redis/redis.conf" }
      async: 120
      poll: 5
      register: config_deployment

    - name: Wait for all configuration deployments
      async_status:
        jid: "{{ item.ansible_job_id }}"
      loop: "{{ config_deployment.results }}"
      when: item.ansible_job_id is defined

  handlers:
    - name: restart services
      service:
        name: "{{ item }}"
        state: restarted
      loop:
        - nginx
        - mysql
        - redis
      listen: "restart all services"
EOF

# Performance monitoring playbook
cat > playbooks/performance-monitoring.yml <<EOF
---
- name: Performance Monitoring Setup
  hosts: all
  become: yes
  vars:
    monitoring_tools:
      - htop
      - iotop
      - nethogs
      - dstat
      - sysstat
      - perf

  tasks:
    - name: Install performance monitoring tools
      package:
        name: "{{ monitoring_tools }}"
        state: present

    - name: Configure system monitoring
      template:
        src: templates/sysstat.j2
        dest: /etc/default/sysstat
        backup: yes
      when: ansible_os_family == "Debian"

    - name: Enable system statistics collection
      service:
        name: "{{ 'sysstat' if ansible_os_family == 'Debian' else 'sysstat' }}"
        enabled: yes
        state: started

    - name: Create performance monitoring script
      template:
        src: templates/performance-monitor.sh.j2
        dest: /usr/local/bin/performance-monitor.sh
        mode: '0755'

    - name: Schedule performance monitoring
      cron:
        name: "Performance monitoring"
        minute: "*/5"
        job: "/usr/local/bin/performance-monitor.sh"
        user: root
EOF
```

## Reverse Proxy Setup

### nginx Configuration for Ansible AWX/Tower

```nginx
# /etc/nginx/sites-available/ansible-awx
upstream ansible_awx {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081 backup;
}

server {
    listen 80;
    listen [::]:80;
    server_name ansible.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ansible.example.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/ansible.example.com.crt;
    ssl_certificate_key /etc/ssl/private/ansible.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        proxy_pass http://ansible_awx;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # WebSocket support
    location /websocket/ {
        proxy_pass http://ansible_awx;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    daemon
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    log stdout local0 info

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend ansible_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/ansible.pem
    redirect scheme https if !{ ssl_fc }
    default_backend ansible_backend

backend ansible_backend
    balance roundrobin
    option httpchk GET /api/v2/ping/
    server awx1 127.0.0.1:8080 check
    server awx2 127.0.0.1:8081 check backup
```

### Apache Configuration

```apache
# /etc/apache2/sites-available/ansible-awx.conf
<VirtualHost *:80>
    ServerName ansible.example.com
    Redirect permanent / https://ansible.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName ansible.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ansible.example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/ansible.example.com.key
    
    # Security headers
    Header always set X-Frame-Options DENY
    Header always set X-Content-Type-Options nosniff
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    ProxyPass /websocket/ ws://127.0.0.1:8080/websocket/
    ProxyPassReverse /websocket/ ws://127.0.0.1:8080/websocket/
    
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

## Monitoring

### Built-in Monitoring and Logging

```bash
# Create comprehensive monitoring playbook
cat > playbooks/ansible-monitoring.yml <<EOF
---
- name: Ansible Infrastructure Monitoring
  hosts: all
  become: yes
  vars:
    monitoring_tools:
      - name: prometheus
        port: 9090
      - name: grafana
        port: 3000
      - name: alertmanager
        port: 9093
    
    log_paths:
      - /var/log/ansible
      - /var/log/awx
      - /var/log/syslog
      - /var/log/auth.log

  tasks:
    # Install monitoring agents
    - name: Install Prometheus Node Exporter
      get_url:
        url: https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
        dest: /tmp/node_exporter.tar.gz
        mode: '0644'

    - name: Extract Node Exporter
      unarchive:
        src: /tmp/node_exporter.tar.gz
        dest: /opt/
        remote_src: yes
        creates: /opt/node_exporter-1.6.1.linux-amd64

    - name: Create node_exporter user
      user:
        name: node_exporter
        system: yes
        shell: /bin/false
        home: /var/lib/node_exporter

    - name: Install Node Exporter binary
      copy:
        src: /opt/node_exporter-1.6.1.linux-amd64/node_exporter
        dest: /usr/local/bin/node_exporter
        mode: '0755'
        owner: node_exporter
        group: node_exporter
        remote_src: yes

    - name: Create Node Exporter service
      template:
        src: templates/node_exporter.service.j2
        dest: /etc/systemd/system/node_exporter.service
      notify: restart node_exporter

    - name: Enable and start Node Exporter
      systemd:
        name: node_exporter
        state: started
        enabled: yes
        daemon_reload: yes

    # Log monitoring setup
    - name: Install rsyslog for centralized logging
      package:
        name: rsyslog
        state: present

    - name: Configure rsyslog for Ansible logs
      template:
        src: templates/ansible-rsyslog.conf.j2
        dest: /etc/rsyslog.d/50-ansible.conf
        backup: yes
      notify: restart rsyslog

    # Create monitoring scripts
    - name: Create Ansible health check script
      template:
        src: templates/ansible-health-check.sh.j2
        dest: /usr/local/bin/ansible-health-check.sh
        mode: '0755'

    - name: Schedule health checks
      cron:
        name: "Ansible health check"
        minute: "*/5"
        job: "/usr/local/bin/ansible-health-check.sh"
        user: root

  handlers:
    - name: restart node_exporter
      systemd:
        name: node_exporter
        state: restarted

    - name: restart rsyslog
      systemd:
        name: rsyslog
        state: restarted
EOF
```

### Prometheus Configuration for Ansible

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "ansible_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'ansible-nodes'
    static_configs:
      - targets:
        - 'ansible-control:9100'
        - 'web-01:9100'
        - 'web-02:9100'
        - 'db-01:9100'

  - job_name: 'ansible-awx'
    static_configs:
      - targets:
        - 'awx-web:8080'
        - 'awx-task:8080'
    metrics_path: '/api/v2/metrics/'
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets:
        - 'node1:9100'
        - 'node2:9100'
        - 'node3:9100'
```

### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "Ansible Infrastructure Monitoring",
    "panels": [
      {
        "title": "Ansible Job Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "(ansible_job_successful_total / ansible_job_total) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      },
      {
        "title": "Node Resource Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
            "legendFormat": "CPU Usage %"
          },
          {
            "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
            "legendFormat": "Memory Usage %"
          }
        ]
      }
    ]
  }
}
```

## Integration Examples

### Python Integration with Ansible

```python
#!/usr/bin/env python3
# ansible_integration.py

import ansible_runner
import subprocess
import json
import os
from pathlib import Path

class AnsibleManager:
    def __init__(self, project_dir, inventory_path):
        self.project_dir = Path(project_dir)
        self.inventory_path = inventory_path
        self.private_data_dir = self.project_dir / 'runner_data'
        
    def run_playbook(self, playbook_name, extra_vars=None, limit=None):
        """Run an Ansible playbook with error handling"""
        try:
            result = ansible_runner.run(
                private_data_dir=str(self.private_data_dir),
                playbook=playbook_name,
                inventory=self.inventory_path,
                extravars=extra_vars or {},
                limit=limit,
                verbosity=1
            )
            
            return {
                'status': result.status,
                'rc': result.rc,
                'stdout': result.stdout.read() if result.stdout else '',
                'stats': result.stats
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def run_ad_hoc_command(self, module, module_args, hosts='all'):
        """Run ad-hoc Ansible commands"""
        try:
            result = ansible_runner.run(
                private_data_dir=str(self.private_data_dir),
                inventory=self.inventory_path,
                module=module,
                module_args=module_args,
                host_pattern=hosts
            )
            
            return {
                'status': result.status,
                'rc': result.rc,
                'events': [event for event in result.events if event['event'] == 'runner_on_ok']
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def get_inventory_info(self):
        """Get inventory information"""
        cmd = ['ansible-inventory', '-i', self.inventory_path, '--list']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            return {'error': e.stderr}

# Example usage
if __name__ == '__main__':
    ansible_mgr = AnsibleManager(
        project_dir='/home/ansible/infrastructure',
        inventory_path='inventories/production/hosts.yml'
    )
    
    # Run a playbook
    result = ansible_mgr.run_playbook(
        'site.yml',
        extra_vars={'environment': 'production'},
        limit='webservers'
    )
    print(f"Playbook execution: {result['status']}")
    
    # Run ad-hoc command
    ping_result = ansible_mgr.run_ad_hoc_command('ping', '', 'all')
    print(f"Ping test: {ping_result['status']}")
    
    # Get inventory info
    inventory = ansible_mgr.get_inventory_info()
    print(f"Managed hosts: {len(inventory.get('_meta', {}).get('hostvars', {}))}")
```

### Node.js Integration

```javascript
// ansible_integration.js
const { spawn, exec } = require('child_process');
const path = require('path');
const fs = require('fs').promises;

class AnsibleManager {
    constructor(projectDir, inventoryPath) {
        this.projectDir = projectDir;
        this.inventoryPath = inventoryPath;
    }
    
    async runPlaybook(playbookName, options = {}) {
        return new Promise((resolve, reject) => {
            const args = [
                'ansible-playbook',
                '-i', this.inventoryPath,
                path.join(this.projectDir, 'playbooks', playbookName)
            ];
            
            if (options.limit) {
                args.push('--limit', options.limit);
            }
            
            if (options.extraVars) {
                args.push('--extra-vars', JSON.stringify(options.extraVars));
            }
            
            if (options.check) {
                args.push('--check');
            }
            
            const process = spawn(args[0], args.slice(1), {
                cwd: this.projectDir,
                stdio: ['pipe', 'pipe', 'pipe']
            });
            
            let stdout = '';
            let stderr = '';
            
            process.stdout.on('data', (data) => {
                stdout += data.toString();
            });
            
            process.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            process.on('close', (code) => {
                resolve({
                    exitCode: code,
                    stdout: stdout,
                    stderr: stderr,
                    success: code === 0
                });
            });
            
            process.on('error', reject);
        });
    }
    
    async runAdHocCommand(module, args, hosts = 'all') {
        return new Promise((resolve, reject) => {
            const command = `ansible ${hosts} -i ${this.inventoryPath} -m ${module} -a "${args}"`;
            
            exec(command, { cwd: this.projectDir }, (error, stdout, stderr) => {
                if (error) {
                    reject({ error, stderr });
                } else {
                    resolve({ stdout, stderr });
                }
            });
        });
    }
    
    async getInventoryInfo() {
        return new Promise((resolve, reject) => {
            const command = `ansible-inventory -i ${this.inventoryPath} --list`;
            
            exec(command, { cwd: this.projectDir }, (error, stdout, stderr) => {
                if (error) {
                    reject({ error, stderr });
                } else {
                    try {
                        resolve(JSON.parse(stdout));
                    } catch (parseError) {
                        reject({ error: parseError, stdout });
                    }
                }
            });
        });
    }
}

// Example usage
async function main() {
    const ansible = new AnsibleManager('/home/ansible/infrastructure', 'inventories/production/hosts.yml');
    
    try {
        // Run playbook
        const result = await ansible.runPlaybook('site.yml', {
            limit: 'webservers',
            extraVars: { environment: 'production' },
            check: true
        });
        console.log('Playbook check result:', result.success);
        
        // Run ad-hoc command
        const pingResult = await ansible.runAdHocCommand('ping', '', 'all');
        console.log('Ping result:', pingResult.stdout);
        
        // Get inventory
        const inventory = await ansible.getInventoryInfo();
        console.log('Inventory hosts:', Object.keys(inventory._meta.hostvars).length);
        
    } catch (error) {
        console.error('Error:', error);
    }
}

if (require.main === module) {
    main();
}

module.exports = AnsibleManager;
```

### REST API Integration

```python
#!/usr/bin/env python3
# ansible_rest_api.py

from flask import Flask, request, jsonify
import ansible_runner
import tempfile
import os
import yaml
from pathlib import Path

app = Flask(__name__)

class AnsibleAPI:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.inventory_file = self.base_dir / 'inventory' / 'hosts.yml'
        
    def execute_playbook(self, playbook_content, inventory_data, extra_vars=None):
        """Execute a playbook with given inventory and variables"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Write playbook
            playbook_file = tmpdir / 'playbook.yml'
            with open(playbook_file, 'w') as f:
                yaml.dump(playbook_content, f, default_flow_style=False)
            
            # Write inventory
            inventory_file = tmpdir / 'inventory.yml'
            with open(inventory_file, 'w') as f:
                yaml.dump(inventory_data, f, default_flow_style=False)
            
            # Run playbook
            result = ansible_runner.run(
                private_data_dir=str(tmpdir),
                playbook='playbook.yml',
                inventory=str(inventory_file),
                extravars=extra_vars or {}
            )
            
            return {
                'status': result.status,
                'rc': result.rc,
                'stats': result.stats,
                'events': [e for e in result.events if e['event'] == 'playbook_on_stats']
            }

ansible_api = AnsibleAPI('/home/ansible')

@app.route('/api/playbook/run', methods=['POST'])
def run_playbook():
    try:
        data = request.get_json()
        
        playbook = data.get('playbook')
        inventory = data.get('inventory')
        extra_vars = data.get('extra_vars', {})
        
        if not playbook or not inventory:
            return jsonify({'error': 'playbook and inventory are required'}), 400
            
        result = ansible_api.execute_playbook(playbook, inventory, extra_vars)
        
        return jsonify({
            'success': result['status'] == 'successful',
            'status': result['status'],
            'return_code': result['rc'],
            'stats': result['stats']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    try:
        with open(ansible_api.inventory_file, 'r') as f:
            inventory = yaml.safe_load(f)
        return jsonify(inventory)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'ansible_version': '2.15.0',  # This should be dynamic
        'base_dir': str(ansible_api.base_dir)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

## Maintenance

### Regular Maintenance Tasks

```bash
#!/bin/bash
# ansible-maintenance.sh - Comprehensive maintenance script

# Set variables
ANSIBLE_HOME="/home/ansible"
LOG_FILE="/var/log/ansible-maintenance.log"
BACKUP_DIR="/backup/ansible"
DATE=$(date +"%Y%m%d_%H%M%S")

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting Ansible maintenance tasks"

# 1. Update Ansible and collections
log "Updating Ansible and collections"
pip install --upgrade ansible ansible-core
ansible-galaxy collection install --upgrade community.general
ansible-galaxy collection install --upgrade ansible.posix
ansible-galaxy collection install --upgrade kubernetes.core

# 2. Clean up old logs
log "Cleaning up old log files"
find "$ANSIBLE_HOME/logs" -type f -name "*.log" -mtime +30 -delete
find /var/log/ansible -type f -name "*.log" -mtime +30 -delete

# 3. Update facts cache
log "Refreshing facts cache"
ansible all -m setup --tree /tmp/facts_cache/

# 4. Validate all playbooks
log "Validating playbooks syntax"
find "$ANSIBLE_HOME/playbooks" -name "*.yml" -exec ansible-playbook {} --syntax-check \;
if [ $? -eq 0 ]; then
    log "All playbooks passed syntax validation"
else
    log "ERROR: Some playbooks failed syntax validation"
fi

# 5. Check inventory health
log "Checking inventory health"
ansible-inventory --list > /tmp/inventory_check.json
if [ $? -eq 0 ]; then
    log "Inventory syntax is valid"
else
    log "ERROR: Inventory has syntax errors"
fi

# 6. Test connectivity to all hosts
log "Testing connectivity to managed hosts"
ansible all -m ping --one-line > "/tmp/ping_results_$DATE.txt"
FAILED_HOSTS=$(grep -c "FAILED" "/tmp/ping_results_$DATE.txt")
if [ "$FAILED_HOSTS" -gt 0 ]; then
    log "WARNING: $FAILED_HOSTS hosts failed connectivity test"
    grep "FAILED" "/tmp/ping_results_$DATE.txt" >> "$LOG_FILE"
else
    log "All hosts are reachable"
fi

# 7. Backup configurations
log "Creating configuration backup"
mkdir -p "$BACKUP_DIR/$DATE"
tar -czf "$BACKUP_DIR/$DATE/ansible-config-$DATE.tar.gz" \
    "$ANSIBLE_HOME"/{ansible.cfg,inventories,group_vars,host_vars,playbooks,roles}

# 8. Clean up old backups (keep 30 days)
log "Cleaning up old backups"
find "$BACKUP_DIR" -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null

# 9. Update SSH known_hosts
log "Updating SSH known_hosts"
for host in $(ansible all --list-hosts | grep -v hosts); do
    ssh-keyscan -H "$host" >> ~/.ssh/known_hosts 2>/dev/null
done
sort -u ~/.ssh/known_hosts > ~/.ssh/known_hosts.tmp && mv ~/.ssh/known_hosts.tmp ~/.ssh/known_hosts

# 10. Generate maintenance report
log "Generating maintenance report"
REPORT_FILE="/tmp/ansible-maintenance-report-$DATE.txt"
cat > "$REPORT_FILE" << EOF
Ansible Maintenance Report - $DATE
========================================

Ansible Version: $(ansible --version | head -1)
Python Version: $(python3 --version)
System: $(uname -a)

Inventory Summary:
$(ansible-inventory --list | jq '."_meta"."hostvars" | keys | length') managed hosts

Connectivity Test Results:
$(wc -l < "/tmp/ping_results_$DATE.txt") total hosts tested
$FAILED_HOSTS hosts failed connectivity

Playbook Validation: $(find "$ANSIBLE_HOME/playbooks" -name "*.yml" | wc -l) playbooks checked

Disk Usage:
$(df -h "$ANSIBLE_HOME" | tail -1)

Backup Created: $BACKUP_DIR/$DATE/ansible-config-$DATE.tar.gz
Backup Size: $(du -sh "$BACKUP_DIR/$DATE/ansible-config-$DATE.tar.gz" | cut -f1)

Recent Log Entries (last 10):
$(tail -10 "$LOG_FILE")
EOF

log "Maintenance report created: $REPORT_FILE"

# 11. Send report via email (optional)
if command -v mail >/dev/null 2>&1; then
    mail -s "Ansible Maintenance Report - $DATE" admin@example.com < "$REPORT_FILE"
    log "Maintenance report emailed"
fi

log "Ansible maintenance tasks completed"

# Schedule this script to run weekly
# Add to crontab: 0 2 * * 0 /usr/local/bin/ansible-maintenance.sh
```

### Ansible Version Management

```bash
#!/bin/bash
# ansible-version-manager.sh - Manage multiple Ansible versions

ANSIBLE_VERSIONS_DIR="/opt/ansible-versions"
CURRENT_LINK="/opt/ansible/current"

install_ansible_version() {
    local version="$1"
    local install_dir="$ANSIBLE_VERSIONS_DIR/$version"
    
    if [ -d "$install_dir" ]; then
        echo "Ansible $version is already installed"
        return 0
    fi
    
    echo "Installing Ansible $version..."
    python3 -m venv "$install_dir"
    source "$install_dir/bin/activate"
    
    pip install --upgrade pip
    pip install "ansible-core==$version"
    pip install ansible
    
    # Install essential collections
    ansible-galaxy collection install community.general
    ansible-galaxy collection install ansible.posix
    ansible-galaxy collection install kubernetes.core
    
    deactivate
    echo "Ansible $version installed successfully"
}

switch_ansible_version() {
    local version="$1"
    local install_dir="$ANSIBLE_VERSIONS_DIR/$version"
    
    if [ ! -d "$install_dir" ]; then
        echo "Ansible $version is not installed"
        echo "Available versions:"
        ls -1 "$ANSIBLE_VERSIONS_DIR" 2>/dev/null || echo "No versions installed"
        return 1
    fi
    
    rm -f "$CURRENT_LINK"
    ln -s "$install_dir" "$CURRENT_LINK"
    
    echo "Switched to Ansible $version"
    echo "Current version: $("$CURRENT_LINK/bin/ansible" --version | head -1)"
}

list_versions() {
    echo "Installed Ansible versions:"
    ls -1 "$ANSIBLE_VERSIONS_DIR" 2>/dev/null || echo "No versions installed"
    
    if [ -L "$CURRENT_LINK" ]; then
        local current=$(readlink "$CURRENT_LINK" | basename)
        echo "Current version: $current"
    else
        echo "No current version set"
    fi
}

remove_version() {
    local version="$1"
    local install_dir="$ANSIBLE_VERSIONS_DIR/$version"
    
    if [ ! -d "$install_dir" ]; then
        echo "Ansible $version is not installed"
        return 1
    fi
    
    if [ "$(readlink "$CURRENT_LINK" 2>/dev/null)" = "$install_dir" ]; then
        echo "Cannot remove currently active version"
        return 1
    fi
    
    rm -rf "$install_dir"
    echo "Removed Ansible $version"
}

case "$1" in
    install)
        install_ansible_version "$2"
        ;;
    switch)
        switch_ansible_version "$2"
        ;;
    list)
        list_versions
        ;;
    remove)
        remove_version "$2"
        ;;
    *)
        echo "Usage: $0 {install|switch|list|remove} [version]"
        echo "Examples:"
        echo "  $0 install 2.15.0"
        echo "  $0 switch 2.15.0"
        echo "  $0 list"
        echo "  $0 remove 2.14.0"
        exit 1
        ;;
esac
```

### Performance Monitoring and Optimization

```bash
#!/bin/bash
# ansible-performance-monitor.sh - Monitor and optimize Ansible performance

log_performance() {
    local playbook="$1"
    local start_time=$(date +%s)
    local log_file="/var/log/ansible-performance.log"
    
    # Run playbook with timing
    /usr/bin/time -v ansible-playbook "$playbook" --extra-vars="gather_facts=True" 2>&1 | \
    tee "/tmp/ansible-run-$start_time.log"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Playbook: $playbook, Duration: ${duration}s" >> "$log_file"
    
    # Extract performance metrics
    local max_memory=$(grep "Maximum resident set size" "/tmp/ansible-run-$start_time.log" | awk '{print $6}')
    local user_time=$(grep "User time" "/tmp/ansible-run-$start_time.log" | awk '{print $4}')
    local system_time=$(grep "System time" "/tmp/ansible-run-$start_time.log" | awk '{print $4}')
    
    echo "Performance Metrics - Memory: ${max_memory}KB, User: ${user_time}s, System: ${system_time}s" >> "$log_file"
    
    # Clean up
    rm "/tmp/ansible-run-$start_time.log"
}

# Example usage in a wrapper script
if [ "$1" = "monitor" ] && [ -n "$2" ]; then
    log_performance "$2"
else
    echo "Usage: $0 monitor <playbook_path>"
    exit 1
fi
```

## Testing and Validation

### Molecule Testing Framework
```bash
# Install Molecule for role testing
pip install molecule[docker] molecule[vagrant] molecule[libvirt]

# Initialize Molecule in role directory
cd roles/nginx
molecule init scenario --driver-name docker

# Create molecule configuration
cat > molecule/default/molecule.yml <<EOF
---
dependency:
  name: galaxy
driver:
  name: docker
platforms:
  - name: nginx-ubuntu
    image: ubuntu:22.04
    pre_build_image: true
    privileged: true
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    command: /lib/systemd/systemd
    networks:
      - name: molecule
  - name: nginx-centos
    image: centos:8
    pre_build_image: true
    privileged: true
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    command: /usr/sbin/init
    networks:
      - name: molecule
provisioner:
  name: ansible
  config_options:
    defaults:
      callbacks_enabled: profile_tasks,timer,yaml
  inventory:
    host_vars:
      nginx-ubuntu:
        ansible_python_interpreter: /usr/bin/python3
      nginx-centos:
        ansible_python_interpreter: /usr/bin/python3
verifier:
  name: ansible
lint: |
  set -e
  yamllint .
  ansible-lint
  flake8
EOF

# Create test playbook
cat > molecule/default/converge.yml <<EOF
---
- name: Converge
  hosts: all
  become: true
  tasks:
    - name: "Include nginx role"
      include_role:
        name: nginx
      vars:
        nginx_vhosts:
          - name: default
            server_name: localhost
            listen: 80
            root: /var/www/html
            enabled: true
EOF

# Create test verification
cat > molecule/default/verify.yml <<EOF
---
- name: Verify
  hosts: all
  gather_facts: false
  tasks:
    - name: Check if NGINX is running
      uri:
        url: http://localhost
        method: GET
      register: nginx_check

    - name: Verify NGINX is responding
      assert:
        that:
          - nginx_check.status == 200
        fail_msg: "NGINX is not responding correctly"

    - name: Check NGINX configuration
      shell: nginx -t
      changed_when: false

    - name: Verify NGINX process
      shell: pgrep nginx
      changed_when: false
EOF

# Run tests
molecule test
```

### Ansible Lint and Security Scanning
```bash
# Install Ansible Lint
pip install ansible-lint

# Create .ansible-lint configuration
cat > .ansible-lint <<EOF
---
profile: production

exclude_paths:
  - .cache/
  - .github/
  - molecule/
  - .venv/

skip_list:
  - yaml[line-length]  # Allow longer lines for readability

warn_list:
  - experimental  # Warn about experimental features

# Custom rules
rules:
  braces:
    min-spaces-inside: 0
    max-spaces-inside: 1
  brackets:
    min-spaces-inside: 0
    max-spaces-inside: 0
  colons:
    max-spaces-before: 0
    min-spaces-after: 1
    max-spaces-after: 1
  commas:
    max-spaces-before: 0
    min-spaces-after: 1
    max-spaces-after: 1
  comments:
    min-spaces-from-content: 1
  document-start: disable
  empty-lines:
    max: 2
    max-start: 0
    max-end: 1
  hyphens:
    max-spaces-after: 1
  indentation:
    spaces: 2
    indent-sequences: true
  line-length:
    max: 120
  new-line-at-end-of-file: enable
  trailing-spaces: enable
  truthy:
    allowed-values: ['true', 'false', 'yes', 'no']
EOF

# Create security-focused playbook linting
cat > .yamllint <<EOF
---
extends: default

rules:
  braces:
    min-spaces-inside: 0
    max-spaces-inside: 1
  brackets:
    min-spaces-inside: 0
    max-spaces-inside: 0
  colons:
    max-spaces-before: 0
    min-spaces-after: 1
    max-spaces-after: 1
  commas:
    max-spaces-before: 0
    min-spaces-after: 1
    max-spaces-after: 1
  comments: disable
  comments-indentation: disable
  document-start: disable
  empty-lines:
    max: 2
    max-start: 0
    max-end: 1
  hyphens:
    max-spaces-after: 1
  indentation:
    spaces: 2
    indent-sequences: true
    check-multi-line-strings: false
  key-duplicates: enable
  line-length:
    max: 120
  new-line-at-end-of-file: enable
  octal-values:
    forbid-implicit-octal: true
  trailing-spaces: enable
  truthy: disable
EOF

# Run linting
ansible-lint playbooks/
yamllint .
```

## Backup and Disaster Recovery

### Comprehensive Backup Automation
```bash
cat > playbooks/backup-automation.yml <<EOF
---
- name: Automated Backup System
  hosts: all
  become: yes
  vars:
    backup_root: /backup
    backup_retention_days: 30
    backup_schedule:
      databases: "0 2 * * *"
      files: "0 3 * * *"
      configs: "0 4 * * *"

  tasks:
    - name: Create backup directories
      file:
        path: "{{ backup_root }}/{{ item }}"
        state: directory
        mode: '0755'
        owner: root
        group: root
      loop:
        - databases
        - files
        - configs
        - logs

    # Database backups
    - name: Create database backup script
      template:
        src: templates/mysql-backup.sh.j2
        dest: /usr/local/bin/mysql-backup.sh
        mode: '0755'
      when: "'dbservers' in group_names"

    - name: Schedule database backups
      cron:
        name: "MySQL backup"
        minute: "0"
        hour: "2"
        job: "/usr/local/bin/mysql-backup.sh"
        user: root
      when: "'dbservers' in group_names"

    # File system backups
    - name: Create file backup script
      template:
        src: templates/file-backup.sh.j2
        dest: /usr/local/bin/file-backup.sh
        mode: '0755'

    - name: Schedule file backups
      cron:
        name: "File system backup"
        minute: "0"
        hour: "3"
        job: "/usr/local/bin/file-backup.sh"
        user: root

    # Configuration backups
    - name: Backup system configurations
      archive:
        path:
          - /etc/nginx
          - /etc/mysql
          - /etc/systemd/system
          - /etc/crontab
          - /etc/hosts
          - /etc/fstab
        dest: "{{ backup_root }}/configs/system-config-{{ ansible_date_time.epoch }}.tar.gz"
        mode: '0600'

    # Remote backup synchronization
    - name: Synchronize backups to remote storage
      synchronize:
        src: "{{ backup_root }}/"
        dest: "backup-server.example.com:{{ backup_root }}/{{ inventory_hostname }}/"
        delete: yes
        rsync_opts:
          - "--exclude=*.tmp"
          - "--compress"
          - "--archive"
      when: backup_remote_sync | default(true)

    # Cleanup old backups
    - name: Clean up old backup files
      find:
        paths: "{{ backup_root }}"
        age: "{{ backup_retention_days }}d"
        file_type: file
      register: old_backups

    - name: Remove old backup files
      file:
        path: "{{ item.path }}"
        state: absent
      loop: "{{ old_backups.files }}"
EOF
```

## Verification and Monitoring

### Cross-Platform System Verification
```bash
# Create comprehensive verification playbook
cat > playbooks/system-verification.yml <<EOF
---
- name: System Verification and Health Check
  hosts: all
  become: yes
  gather_facts: yes
  vars:
    health_checks:
      - service: nginx
        port: 80
        process: nginx
      - service: mysql
        port: 3306
        process: mysqld
      - service: redis
        port: 6379
        process: redis-server

  tasks:
    # System information gathering
    - name: Gather system information
      setup:
        gather_subset:
          - all
          - !facter
          - !ohai

    # Service verification
    - name: Check critical services status
      service_facts:

    - name: Verify services are running
      assert:
        that:
          - "ansible_facts.services[item.service + '.service'].state == 'running'"
        fail_msg: "Service {{ item.service }} is not running"
        success_msg: "Service {{ item.service }} is healthy"
      loop: "{{ health_checks }}"
      when: "item.service + '.service' in ansible_facts.services"

    # Network connectivity tests
    - name: Test network connectivity
      wait_for:
        host: "{{ item.host }}"
        port: "{{ item.port }}"
        timeout: 5
      loop:
        - { host: "8.8.8.8", port: 53 }
        - { host: "1.1.1.1", port: 53 }
      ignore_errors: yes

    # Disk space monitoring
    - name: Check disk space usage
      shell: df -h | awk '$5 > "85%" {print $0}'
      register: disk_usage
      changed_when: false
      failed_when: disk_usage.stdout != ""

    # Memory usage check
    - name: Check memory usage
      shell: free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}'
      register: memory_usage
      changed_when: false

    - name: Alert on high memory usage
      debug:
        msg: "WARNING: Memory usage is {{ memory_usage.stdout }}%"
      when: memory_usage.stdout | int > 85

    # Security verification
    - name: Check for failed login attempts
      shell: grep "Failed password" /var/log/auth.log | tail -10
      register: failed_logins
      changed_when: false
      ignore_errors: yes
      when: ansible_os_family == "Debian"

    - name: Check firewall status
      shell: |
        if command -v ufw >/dev/null 2>&1; then
          ufw status
        elif command -v firewall-cmd >/dev/null 2>&1; then
          firewall-cmd --state
        else
          echo "No supported firewall found"
        fi
      register: firewall_status
      changed_when: false

  post_tasks:
    - name: Generate system health report
      template:
        src: templates/health-report.j2
        dest: "/tmp/health-report-{{ inventory_hostname }}-{{ ansible_date_time.epoch }}.txt"
        mode: '0644'

    - name: Fetch health reports
      fetch:
        src: "/tmp/health-report-{{ inventory_hostname }}-{{ ansible_date_time.epoch }}.txt"
        dest: "./reports/"
        flat: yes
EOF
```

### Continuous Compliance Monitoring
```bash
cat > playbooks/compliance-monitoring.yml <<EOF
---
- name: Continuous Compliance Monitoring
  hosts: all
  become: yes
  vars:
    compliance_standards:
      - cis
      - pci_dss
      - soc2
      - hipaa
    
    audit_log_paths:
      - /var/log/auth.log
      - /var/log/syslog
      - /var/log/audit/audit.log

  tasks:
    # Install audit tools
    - name: Install audit daemon
      package:
        name: "{{ 'auditd' if ansible_os_family == 'RedHat' else 'auditd' }}"
        state: present

    - name: Configure audit rules
      template:
        src: templates/audit.rules.j2
        dest: /etc/audit/rules.d/audit.rules
        backup: yes
      notify: restart auditd

    # CIS compliance checks
    - name: Run CIS benchmark checks
      shell: |
        if [ -f /opt/cis-cat/CIS-CAT.sh ]; then
          /opt/cis-cat/CIS-CAT.sh -b /opt/cis-cat/benchmarks/
        else
          echo "CIS-CAT not installed, skipping"
        fi
      register: cis_results
      ignore_errors: yes

    # File integrity monitoring
    - name: Install AIDE
      package:
        name: aide
        state: present

    - name: Initialize AIDE database
      shell: |
        aide --init
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      args:
        creates: /var/lib/aide/aide.db

    - name: Schedule AIDE integrity checks
      cron:
        name: "AIDE integrity check"
        minute: "0"
        hour: "3"
        job: "/usr/bin/aide --check | mail -s 'AIDE Report' security@example.com"
        user: root

    # Log monitoring
    - name: Install log monitoring tools
      package:
        name:
          - logwatch
          - rsyslog
        state: present

    - name: Configure centralized logging
      template:
        src: templates/rsyslog.conf.j2
        dest: /etc/rsyslog.conf
        backup: yes
      notify: restart rsyslog

  handlers:
    - name: restart auditd
      service:
        name: auditd
        state: restarted

    - name: restart rsyslog
      service:
        name: rsyslog
        state: restarted
EOF
```

## CI/CD Integration

### Jenkins Pipeline Integration
```bash
# Create Jenkinsfile for Ansible automation
cat > Jenkinsfile <<EOF
pipeline {
    agent any
    
    environment {
        ANSIBLE_CONFIG = 'ansible.cfg'
        ANSIBLE_HOST_KEY_CHECKING = 'False'
    }
    
    stages {
        stage('Lint') {
            steps {
                sh 'ansible-lint playbooks/'
                sh 'yamllint .'
            }
        }
        
        stage('Syntax Check') {
            steps {
                sh 'ansible-playbook playbooks/site.yml --syntax-check'
            }
        }
        
        stage('Dry Run') {
            steps {
                sh 'ansible-playbook playbooks/site.yml --check --diff'
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                sh 'ansible-playbook -i inventories/staging playbooks/site.yml'
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                input 'Deploy to Production?'
                sh 'ansible-playbook -i inventories/production playbooks/site.yml'
            }
        }
        
        stage('Verify Deployment') {
            steps {
                sh 'ansible-playbook playbooks/system-verification.yml'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'logs/*.log', allowEmptyArchive: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: '*.html',
                reportName: 'Ansible Report'
            ])
        }
        failure {
            emailext (
                subject: "Failed Pipeline: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Something is wrong with ${env.BUILD_URL}",
                to: "${env.DEFAULT_RECIPIENTS}"
            )
        }
    }
}
EOF
```

### GitLab CI Integration
```bash
cat > .gitlab-ci.yml <<EOF
stages:
  - lint
  - test
  - deploy-staging
  - deploy-production

variables:
  ANSIBLE_CONFIG: ansible.cfg
  ANSIBLE_HOST_KEY_CHECKING: "False"

before_script:
  - pip install ansible ansible-lint yamllint
  - ansible-galaxy install -r requirements.yml

lint:
  stage: lint
  script:
    - ansible-lint playbooks/
    - yamllint .
  rules:
    - if: '$CI_MERGE_REQUEST_IID'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

syntax-check:
  stage: test
  script:
    - ansible-playbook playbooks/site.yml --syntax-check
    - ansible-playbook playbooks/site.yml --check --diff -i inventories/staging
  rules:
    - if: '$CI_MERGE_REQUEST_IID'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

deploy-staging:
  stage: deploy-staging
  script:
    - ansible-playbook -i inventories/staging playbooks/site.yml
  rules:
    - if: '$CI_COMMIT_BRANCH == "develop"'

deploy-production:
  stage: deploy-production
  script:
    - ansible-playbook -i inventories/production playbooks/site.yml
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      when: manual
  environment:
    name: production
    url: https://production.example.com
EOF
```

## 6. Troubleshooting (Cross-Platform)

### Common Issues and Solutions
```bash
# Debug connection issues
ansible all -m ping -vvv

# Check SSH connectivity
ansible all -m setup --ask-pass --ask-become-pass

# Verify inventory
ansible-inventory --list
ansible-inventory --graph

# Test specific host
ansible target-host -m command -a "uptime"

# Check syntax without execution
ansible-playbook playbooks/site.yml --syntax-check

# Dry run with verbose output
ansible-playbook playbooks/site.yml --check --diff -vvv

# Debug variable resolution
ansible-playbook playbooks/site.yml --extra-vars="debug=true" --tags debug

# Check facts
ansible all -m setup | grep ansible_os_family

# Connection troubleshooting
ssh -vvv user@target-host

# Permission issues
ansible all -m file -a "path=/tmp/test state=touch" --become

# Vault issues
ansible-vault view group_vars/all/vault.yml

# Performance debugging
ansible-playbook playbooks/site.yml --start-at-task="specific task name"
ansible-playbook playbooks/site.yml --step

# Module testing
ansible localhost -m debug -a "var=hostvars"
ansible localhost -m setup

# Check for syntax errors in roles
find roles/ -name "*.yml" -exec ansible-playbook {} --syntax-check \;
```

### Advanced Debugging
```bash
# Enable comprehensive logging
export ANSIBLE_DEBUG=1
export ANSIBLE_VERBOSITY=4
ansible-playbook playbooks/site.yml

# Profile playbook execution
ansible-playbook playbooks/site.yml --extra-vars="profile_tasks_sort_order=none"

# Memory usage analysis
ansible-playbook playbooks/site.yml --extra-vars="ansible_python_interpreter=/usr/bin/python3"

# Network debugging
ansible all -m command -a "ss -tulpn"
ansible all -m command -a "netstat -rn"

# Process debugging
ansible all -m command -a "ps aux --sort=-%mem | head -10"

# Disk usage analysis
ansible all -m command -a "df -h"
ansible all -m command -a "du -sh /var/log/*"

# Service debugging
ansible all -m systemd -a "name=nginx" --become
ansible all -m command -a "systemctl status nginx" --become

# Variable debugging
ansible-playbook playbooks/site.yml --extra-vars="debug_vars=true" --tags debug_vars
```

## Additional Resources

- [Official Documentation](https://docs.ansible.com/)
- [Ansible Galaxy](https://galaxy.ansible.com/)
- [Best Practices Guide](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [Security Best Practices](https://docs.ansible.com/ansible/latest/user_guide/become.html#security-best-practices)
- [Ansible Molecule Testing](https://molecule.readthedocs.io/)
- [Community Collections](https://docs.ansible.com/ansible/latest/collections/index.html)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection.