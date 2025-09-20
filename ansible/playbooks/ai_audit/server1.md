# AI audit server1

## Summary

This report analyzes security information from `server1`, based on system configuration data and a Lynis security scan. The Linpeas and Rkhunter reports provided were empty or contained errors, so no findings could be extracted from them.

The analysis identified several **critical** vulnerabilities that require immediate attention. The most severe finding is a **leaked Google Gemini API key** visible in a running process, which must be revoked immediately. The server is operating **without an active firewall**, leaving all services, including SSH (port 22) and Postfix SMTP (port 25), fully exposed to the internet at `46.62.194.204`.

Further high-risk issues include a lack of kernel hardening, numerous insecure default configurations for system services, and an easily targeted SSH service. Medium-severity findings relate to weak password policies, improper file permissions, and missing security tools like Fail2Ban.

This report provides specific, actionable remediation steps, including Ansible automation tasks and nftables firewall rules, to address these findings and improve the overall security posture of `server1`.

---

## Misconfigurations with ansible mitigations

### Critical

**1. Leaked API Key in Process List**

A Google Gemini API key was found exposed in plain text in the command line arguments of a running process. This allows anyone with access to the process list on the server to steal and misuse the credential.

*   **Evidence:**
    *   Running Process: `root 641557 0.0 0.0 2800 1664 pts/1 Ss+ 08:04 0:00 /bin/sh -c GEMINI_API_KEY=******** /usr/bin/python3.12 ...`
*   **Immediate Remediation:**
    1.  **Revoke the exposed API key `********` immediately** in your Google Cloud Platform console.
    2.  Identify the script or application (`/root/.ansible/tmp/ansible-tmp-1758701061.484395-53122-29017310700592/AnsiballZ_command.py`) that is using this key and modify it to use a secure secrets management tool (e.g., Ansible Vault, HashiCorp Vault) instead of command-line arguments or environment variables.

*   **Ansible Mitigation (Prevention):**
    This Ansible task does not fix the current leak but helps prevent future leaks by scanning for similar key patterns in common configuration directories. It should be adapted and run regularly.

    ```yaml
    - name: Scan for hardcoded API keys in /root
      ansible.builtin.find:
        paths: /root
        recurse: yes
        patterns:
          - "*AIzaSy[A-Za-z0-9_-]{33}*"
      register: found_keys
      changed_when: false
      failed_when: false

    - name: Alert if hardcoded API keys are found
      ansible.builtin.debug:
        msg: "WARNING: Found potential hardcoded API key in file {{ item.path }}"
      loop: "{{ found_keys.files }}"
      when: found_keys.files | length > 0
    ```

### High

**1. Insecure SSH Server Configuration**

The SSH service is configured with default settings that increase its attack surface. Lynis suggests multiple hardening improvements.

*   **Evidence:**
    *   Lynis Finding `[SSH-7408]`: Suggestions to change `AllowTcpForwarding`, `ClientAliveCountMax`, `LogLevel`, `MaxAuthTries`, `MaxSessions`, `Port`, `TCPKeepAlive`, `X11Forwarding`, and `AllowAgentForwarding`.
*   **Ansible Mitigation:**
    This task applies the recommended SSH hardening settings to `/etc/ssh/sshd_config`.

    ```yaml
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^#?{{ item.key }}.*"
        line: "{{ item.key }} {{ item.value }}"
        state: present
        validate: /usr/sbin/sshd -t -f %s
      loop:
        - { key: 'LogLevel', value: 'VERBOSE' }
        - { key: 'MaxAuthTries', value: '3' }
        - { key: 'MaxSessions', value: '2' }
        - { key: 'Port', value: '22' } # Consider changing to a non-standard port
        - { key: 'AllowTcpForwarding', value: 'no' }
        - { key: 'ClientAliveCountMax', value: '2' }
        - { key: 'TCPKeepAlive', value: 'no' }
        - { key: 'X11Forwarding', value: 'no' }
        - { key: 'AllowAgentForwarding', value: 'no' }
      notify: Restart sshd

    - name: Define handler to restart sshd
      ansible.builtin.systemd:
        name: sshd
        state: restarted
      listen: "Restart sshd"
    ```

**2. Insecure Postfix (SMTP) Configuration**

The Postfix mail server discloses its software version in the SMTP banner and has the `VRFY` command enabled, which can be used by attackers to enumerate valid email users.

*   **Evidence:**
    *   Lynis Finding `[MAIL-8818]`: `Found some information disclosure in SMTP banner`.
    *   Lynis Finding `[MAIL-8820]`: `disable_vrfy_command=no`.
*   **Ansible Mitigation:**
    This task hardens the Postfix configuration using the `postconf` module.

    ```yaml
    - name: Harden Postfix configuration
      community.general.postconf:
        param: "{{ item.param }}"
        value: "{{ item.value }}"
        state: present
      loop:
        - { param: 'smtpd_banner', value: '$myhostname ESMTP' }
        - { param: 'disable_vrfy_command', value: 'yes' }
      notify: Restart postfix

    - name: Define handler to restart postfix
      ansible.builtin.systemd:
        name: postfix
        state: restarted
      listen: "Restart postfix"
    ```

### Medium

**1. Weak System-Wide Password Policies**

The system does not enforce password complexity, minimum/maximum age, or use sufficient hashing rounds, making user accounts susceptible to brute-force attacks.

*   **Evidence:**
    *   Lynis Finding `[AUTH-9230]`: `Configure password hashing rounds in /etc/login.defs`.
    *   Lynis Finding `[AUTH-9262]`: `Install a PAM module for password strength testing`.
    *   Lynis Finding `[AUTH-9286]`: `Configure minimum password age` and `maximum password age`.
*   **Ansible Mitigation:**
    This task configures password aging and hashing rounds in `/etc/login.defs` and installs the `libpam-pwquality` package for strength checking.

    ```yaml
    - name: Install PAM password quality module
      ansible.builtin.apt:
        name: libpam-pwquality
        state: present

    - name: Configure password policies in login.defs
      ansible.builtin.lineinfile:
        path: /etc/login.defs
        regexp: "^#?{{ item.key }}.*"
        line: "{{ item.key }} {{ item.value }}"
        state: present
      loop:
        - { key: 'PASS_MAX_DAYS', value: '90' }
        - { key: 'PASS_MIN_DAYS', value: '7' }
        - { key: 'PASS_WARN_AGE', value: '14' }
        - { key: 'SHA_CRYPT_MIN_ROUNDS', value: '500000' }
        - { key: 'SHA_CRYPT_MAX_ROUNDS', value: '1000000' }
    ```

**2. Insecure File Permissions for Cron**

System cron directories and files have overly permissive settings, which could allow unauthorized users to view or modify scheduled tasks.

*   **Evidence:**
    *   Lynis Finding `[FILE-7524]`: Suggests restricting permissions for `/etc/crontab`, `/etc/cron.d`, `/etc/cron.daily`, etc.
    *   System Info: `/etc/crontab` has permissions `-rw-r--r--` (644).
*   **Ansible Mitigation:**
    This task restricts permissions on system cron files and directories.

    ```yaml
    - name: Harden cron file and directory permissions
      ansible.builtin.file:
        path: "{{ item.path }}"
        owner: root
        group: root
        mode: "{{ item.mode }}"
      loop:
        - { path: '/etc/crontab', mode: '0600' }
        - { path: '/etc/cron.d', mode: '0700' }
        - { path: '/etc/cron.daily', mode: '0700' }
        - { path: '/etc/cron.weekly', mode: '0700' }
        - { path: '/etc/cron.monthly', mode: '0700' }
    ```

---

## Vulnerabilities with ansible mitigations

### Critical

**1. No Active Firewall**

The server has the `iptables` kernel module loaded but no active firewall rules. This means all listening services are directly exposed to the internet.

*   **Evidence:**
    *   Lynis Finding `[FIRE-4512]`: `iptables module(s) loaded, but no rules active`.
    *   System Info: The "FIREWALL RULES" section is empty.
*   **Remediation (nftables):**
    Create a file at `/etc/nftables.conf` with the following content. This configuration establishes a default-deny policy and only allows traffic for loopback, established connections, ICMP (ping), SSH (port 22), and SMTP (port 25).

    ```nftables
    #!/usr/sbin/nft -f

    flush ruleset

    table inet filter {
        chain input {
            type filter hook input priority 0;
            policy drop;

            # Allow loopback traffic
            iifname "lo" accept

            # Allow established and related connections
            ct state established,related accept

            # Allow ICMP (ping)
            ip protocol icmp accept
            ip6 nexthdr icmpv6 accept

            # Allow SSH and SMTP from any source
            # WARNING: Restrict source IPs if possible
            tcp dport { 22, 25 } accept
        }

        chain forward {
            type filter hook forward priority 0;
            policy drop;
        }

        chain output {
            type filter hook output priority 0;
            policy accept;
        }
    }
    ```

*   **Ansible Mitigation:**
    This task installs `nftables`, deploys the configuration file, and enables the service.

    ```yaml
    - name: Install nftables package
      ansible.builtin.apt:
        name: nftables
        state: present

    - name: Deploy nftables configuration
      ansible.builtin.copy:
        src: files/nftables.conf # Assumes the content above is in this local file
        dest: /etc/nftables.conf
        owner: root
        group: root
        mode: '0640'
      notify: Restart nftables

    - name: Enable and start nftables service
      ansible.builtin.systemd:
        name: nftables
        state: started
        enabled: yes

    - name: Define handler to restart nftables
      ansible.builtin.systemd:
        name: nftables
        state: restarted
      listen: "Restart nftables"
    ```

### High

**1. Insufficient Kernel Hardening**

Multiple kernel `sysctl` parameters are not configured securely, leaving the system vulnerable to various network-based attacks and information leaks.

*   **Evidence:**
    *   Lynis Finding `[KRNL-6000]`: `One or more sysctl values differ from the scan profile`.
    *   Specific differing keys include: `dev.tty.ldisc_autoload`, `fs.suid_dumpable`, `kernel.kptr_restrict`, `net.ipv4.conf.all.accept_redirects`, `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.all.rp_filter`, etc.
*   **Ansible Mitigation:**
    This task applies the recommended kernel hardening parameters. A new file is created in `/etc/sysctl.d/` to ensure settings persist across reboots.

    ```yaml
    - name: Apply kernel hardening settings
      ansible.posix.sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        sysctl_file: /etc/sysctl.d/99-hardening.conf
        state: present
        reload: yes
      loop:
        - { key: 'dev.tty.ldisc_autoload', value: '0' }
        - { key: 'fs.protected_fifos', value: '2' }
        - { key: 'fs.suid_dumpable', value: '0' }
        - { key: 'kernel.core_uses_pid', value: '1' }
        - { key: 'kernel.kptr_restrict', value: '2' }
        - { key: 'kernel.sysrq', value: '0' }
        - { key: 'kernel.unprivileged_bpf_disabled', value: '1' }
        - { key: 'net.core.bpf_jit_harden', value: '2' }
        - { key: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { key: 'net.ipv4.conf.all.rp_filter', value: '1' }
        - { key: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.accept_redirects', value: '0' }
        - { key: 'net.ipv4.conf.default.log_martians', value: '1' }
        - { key: 'net.ipv6.conf.all.accept_redirects', value: '0' }
        - { key: 'net.ipv6.conf.default.accept_redirects', value: '0' }
    ```

### Medium

**1. Missing Brute-Force Protection**

The `fail2ban` service is not installed. With the SSH service exposed to the internet, the server is highly susceptible to automated password guessing attacks.

*   **Evidence:**
    *   Lynis Finding `[DEB-0880]`: `Install fail2ban to automatically ban hosts that commit multiple authentication errors`.
*   **Ansible Mitigation:**
    This task installs and enables `fail2ban`. A basic local jail configuration is created to protect SSH.

    ```yaml
    - name: Install fail2ban
      ansible.builtin.apt:
        name: fail2ban
        state: present

    - name: Create local jail configuration for SSH
      ansible.builtin.copy:
        dest: /etc/fail2ban/jail.local
        content: |
          [sshd]
          enabled = true
          port = ssh
          logpath = %(sshd_log)s
          backend = %(sshd_backend)s
          maxretry = 3
          bantime = 1h
        owner: root
        group: root
        mode: '0644'
      notify: Restart fail2ban

    - name: Enable and start fail2ban service
      ansible.builtin.systemd:
        name: fail2ban
        state: started
        enabled: yes

    - name: Define handler to restart fail2ban
      ansible.builtin.systemd:
        name: fail2ban
        state: restarted
      listen: "Restart fail2ban"
    ```

---

## General recommendations to increase security of host

1.  **Implement Secrets Management:** The critical API key leak highlights the need for a secure method of handling credentials. Never pass secrets as command-line arguments or store them in plain-text files. Use tools like **Ansible Vault** for encrypted storage in your automation or a dedicated secrets manager like **HashiCorp Vault**.

2.  **Restrict Firewall Access:** The provided firewall rules allow SSH and SMTP access from any IP address. For significantly improved security, **restrict access to these ports to only trusted IP addresses or networks**.

3.  **Systematic Service Hardening:** The Lynis report flagged dozens of systemd services as `UNSAFE`. Review critical services (e.g., `cron`, `atd`, `sshd`) and apply hardening options via systemd drop-in configuration files (in `/etc/systemd/system/service.name.d/`). Key properties include `PrivateTmp=true`, `ProtectSystem=full`, and `NoNewPrivileges=true`.

4.  **Enable Auditing and Centralized Logging:** The system lacks a host-based audit daemon (`auditd`) and does not forward logs to a remote server. Install and configure `auditd` to monitor for suspicious activity. Configure `rsyslog` to forward all system logs to a secure, centralized log management solution to ensure log integrity and aid in incident response.

5.  **Implement File Integrity Monitoring:** Install a tool like **AIDE (Advanced Intrusion Detection Environment)** or **Tripwire**. This will create a baseline of critical system files and alert you to any unauthorized modifications, which is a key indicator of a system compromise.

6.  **Maintain System and Perform Reboots:** The Lynis report indicated that a reboot is needed (`[KRNL-5830]`), likely due to a pending kernel update. Ensure that security patches are applied regularly using the configured `unattended-upgrades` service and that the system is rebooted in a timely manner to activate new kernels.