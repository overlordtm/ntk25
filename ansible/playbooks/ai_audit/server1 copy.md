# AI audit server1

## Summary

This report summarizes the security findings from server1 based on the provided system information, Lynis report, Linpeas report, and Rkhunter report. The analysis identifies several misconfigurations and potential vulnerabilities, along with recommended remediation steps using Ansible.

## Misconfigurations with ansible mitigations

### Critical

*   **Root user logged in via SSH from 212.30.92.138:** This is a critical vulnerability as it allows direct root access to the server.

    **Remediation:** Disable root login via SSH.

    ```yaml
    - name: Disallow root login via SSH
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: PermitRootLogin no
      notify: restart sshd
    
    handlers:
      - name: restart sshd
        ansible.builtin.systemd:
          name: sshd
          state: restarted
    ```

### High

*   **Root ALL=(ALL) NOPASSWD:ALL in sudoers:** This allows root to execute any command without a password, which is a major security risk.

    **Remediation:** Remove the NOPASSWD option for root.

    ```yaml
    - name: Remove NOPASSWD for root in sudoers
      ansible.builtin.lineinfile:
        path: /etc/sudoers
        regexp: '^root ALL=\\(ALL\\) NOPASSWD:ALL'
        state: absent
    ```

*   **systemd-analyze security reports multiple services as UNSAFE:** This indicates that these services have relaxed security policies and could be exploited.

    **Remediation:** Harden system services.

    ```yaml
    - name: Harden system services
      ansible.builtin.command:
        cmd: systemd-analyze security {{ item }}
      loop:
        - acpid.service
        - atd.service
        - cron.service
        - dbus.service
        - dm-event.service
        - dmesg.service
        - emergency.service
        - getty@tty1.service
        - iscsid.service
        - lvm2-lvmpolld.service
        - lynis.service
        - multipathd.service
        - networkd-dispatcher.service
        - open-vm-tools.service
        - plymouth-start.service
        - postfix@-.service
        - qemu-guest-agent.service
        - rc-local.service
        - rescue.service
        - serial-getty@ttyS0.service
        - snapd.service
        - ssh.service
        - systemd-ask-password-console.service
        - systemd-ask-password-plymouth.service
        - systemd-ask-password-wall.service
        - systemd-bsod.service
        - systemd-fsckd.service
        - systemd-initctl.service
        - systemd-rfkill.service
        - tpm-udev.service
        - ubuntu-advantage.service
        - unattended-upgrades.service
        - user@0.service
        - vgauth.service
      register: security_analysis
      failed_when: security_analysis.rc != 0
      changed_when: false
    ```

### Medium

*   **SUID/SGID files:** The presence of SUID/SGID files can be a security risk if not properly managed.

    **Remediation:** Review SUID/SGID files and remove unnecessary permissions.

    ```yaml
    - name: Remove SUID bit from at
      ansible.builtin.file:
        path: /usr/bin/at
        mode: 0755
    ```

*   **Empty iptables ruleset:** The Lynis report indicates that the iptables module is loaded, but no rules are active. This leaves the system vulnerable to network attacks.

    **Remediation:** Implement a basic firewall ruleset using nftables.

    ```nft
    flush ruleset

    table inet filter {
        chain input {
            type filter hook input priority 0; policy drop;
            ct state invalid drop
            ct state {established, related} accept
            iif lo accept

            # SSH
            tcp dport 22 ct state new accept

            # ICMP
            icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
            ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept

            # Logging
            log prefix "nftables-drop: "
            reject with icmpx type admin-prohibited
        }

        chain forward {
            type filter hook forward priority 0; policy drop;
        }

        chain output {
            type filter hook output priority 0; policy accept;
        }
    }
    ```

    ```yaml
    - name: Deploy nftables configuration
      ansible.builtin.copy:
        dest: /etc/nftables.conf
        content: |
          flush ruleset

          table inet filter {
              chain input {
                  type filter hook input priority 0; policy drop;
                  ct state invalid drop
                  ct state {established, related} accept
                  iif lo accept

                  # SSH
                  tcp dport 22 ct state new accept

                  # ICMP
                  icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
                  ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept

                  # Logging
                  log prefix "nftables-drop: "
                  reject with icmpx type admin-prohibited
              }

              chain forward {
                  type filter hook forward priority 0; policy drop;
              }

              chain output {
                  type filter hook output priority 0; policy accept;
              }
          }
      notify: reload nftables

    handlers:
      - name: reload nftables
        ansible.builtin.systemd:
          name: nftables
          state: reloaded
    ```

*   **Weak /etc/issue and /etc/issue.net:** The Lynis report identifies the contents of `/etc/issue` and `/etc/issue.net` as weak. These files are displayed before login and can reveal sensitive system information.

    **Remediation:** Add a legal banner to `/etc/issue` and `/etc/issue.net`.

    ```yaml
    - name: Add legal banner to /etc/issue
      ansible.builtin.copy:
        dest: /etc/issue
        content: |
          Unauthorized access to this system is prohibited.
          All activity is logged and monitored.
    
    - name: Add legal banner to /etc/issue.net
      ansible.builtin.copy:
        dest: /etc/issue.net
        content: |
          Unauthorized access to this system is prohibited.
          All activity is logged and monitored.
    ```

*   **Postfix banner information disclosure:** The Lynis report warns about information disclosure in the SMTP banner.

    **Remediation:** Hide the mail_name from the Postfix configuration.

    ```yaml
    - name: Hide mail_name from Postfix configuration
      ansible.builtin.command:
        cmd: postconf -e smtpd_banner="\$myhostname ESMTP"
      notify: restart postfix
    
    - name: Disable VRFY command
      ansible.builtin.command:
        cmd: postconf -e disable_vrfy_command=yes
      notify: restart postfix
    
    handlers:
      - name: restart postfix
        ansible.builtin.systemd:
          name: postfix
          state: restarted
    ```

### Low

*   **SSH configuration suggestions:** Lynis provides several suggestions for hardening the SSH configuration.

    **Remediation:** Implement the suggested SSH hardening measures.

    ```yaml
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^AllowTcpForwarding'
        line: AllowTcpForwarding no
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^ClientAliveCountMax'
        line: ClientAliveCountMax 2
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^LogLevel'
        line: LogLevel VERBOSE
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^MaxAuthTries'
        line: MaxAuthTries 3
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^MaxSessions'
        line: MaxSessions 2
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^TCPKeepAlive'
        line: TCPKeepAlive no
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^X11Forwarding'
        line: X11Forwarding no
      notify: restart sshd
    
    - name: Harden SSH configuration
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^AllowAgentForwarding'
        line: AllowAgentForwarding no
      notify: restart sshd
    
    handlers:
      - name: restart sshd
        ansible.builtin.systemd:
          name: sshd
          state: restarted
    ```

*   **Missing security repository in sources.list:** The Lynis report indicates that no security repository is found in `/etc/apt/sources.list` or `/etc/apt/sources.list.d` directory.

    **Remediation:** Add a security repository to `/etc/apt/sources.list`.

    ```yaml
    - name: Add security repository to sources.list
      ansible.builtin.lineinfile:
        path: /etc/apt/sources.list
        line: deb http://security.ubuntu.com/ubuntu/ noble-security main restricted universe multiverse
        state: present
      notify: update apt cache
    
    handlers:
      - name: update apt cache
        ansible.builtin.apt:
          update_cache: yes
    ```

## Vulnerabilities with ansible mitigations

### High

*   **Reboot needed:** The Lynis report indicates that a reboot is needed.

    **Remediation:** Reboot the system.

    ```yaml
    - name: Reboot the system
      ansible.builtin.reboot:
        reboot_timeout: 300
    ```

## General recommendations to increase security of host

*   **Install security tools:** Install tools like `apt-listbugs`, `apt-listchanges`, and `fail2ban` to enhance security monitoring and incident response.
*   **Configure password aging:** Configure minimum and maximum password ages in `/etc/login.defs` to enforce password rotation.
*   **Harden kernel parameters:** Review and adjust kernel parameters based on the Lynis report to improve system security.
*   **Install a file integrity tool:** Install a file integrity tool like AIDE or Tripwire to monitor changes to critical system files.
*   **Enable process accounting:** Enable process accounting to track user activity and identify potential security incidents.
*   **Regularly update the system:** Keep the system up-to-date with the latest security patches and updates.
*   **Monitor logs:** Regularly monitor system logs for suspicious activity.
*   **Implement intrusion detection system (IDS):** Consider implementing an IDS to detect and respond to malicious activity.
*   **Disable unnecessary services:** Disable any services that are not required for the system's functionality.
*   **Review user accounts:** Regularly review user accounts and remove any unnecessary or inactive accounts.
*   **Implement multi-factor authentication (MFA):** Implement MFA for all user accounts to enhance authentication security.
*   **Harden compilers:** Harden compilers by restricting access to the root user only.
*   **Disable USB storage when not used:** Disable USB storage when not used to prevent unauthorized storage or data theft.
*   **Check DNS configuration:** Check DNS configuration for the dns domain name.
*   **Install debsums utility:** Install debsums utility for the verification of packages with known good database.
*   **Install package apt-show-versions:** Install package apt-show-versions for patch management purposes.
*   **Determine if protocol is really needed on this system:** Determine if protocol 'dccp', 'sctp', 'rds', 'tipc' is really needed on this system.
*   **Enable logging to an external logging host:** Enable logging to an external logging host for archiving purposes and additional protection.
*   **Check what deleted files are still in use and why:** Check what deleted files are still in use and why.
*   **Enable sysstat to collect accounting:** Enable sysstat to collect accounting (disabled).
*   **Enable auditd to collect audit information:** Enable auditd to collect audit information.
*   **Consider restricting file permissions:** Consider restricting file permissions.
*   **One or more sysctl values differ from the scan profile and could be tweaked:** One or more sysctl values differ from the scan profile and could be tweaked.
*   **Harden compilers like restricting access to root user only:** Harden compilers like restricting access to root user only.
*   **Set a password on GRUB boot loader:** Set a password on GRUB boot loader to prevent altering boot configuration (e.g. boot in single user mode without password).
*   **If not required, consider explicit disabling of core dump:** If not required, consider explicit disabling of core dump in /etc/security/limits.conf file.
*   **Configure password hashing rounds:** Configure password hashing rounds in /etc/login.defs.
*   **Install a PAM module for password strength testing:** Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc.
*   **Configure minimum password age:** Configure minimum password age in /etc/login.defs.
*   **Configure maximum password age:** Configure maximum password age in /etc/login.defs.
*   **Default umask in /etc/login.defs could be more strict:** Default umask in /etc/login.defs could be more strict like 027.
*   **To decrease the impact of a full file system, place on a separate partition:** To decrease the impact of a full /home, /tmp, /var file system, place on a separate partition.
