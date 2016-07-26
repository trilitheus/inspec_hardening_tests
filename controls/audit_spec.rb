control 'cis-logging-5.2.1.1' do
  impact 1.0
  title 'Configure Data Retention'
  desc "It is important that an appropriate size is determined for log files so that they do not impact
        the system and audit data is not lost."
  tag logging: 'audit'

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file\s+=\s+/) } # TODO: add size this should be set to
  end
end

control 'cis-logging-5.2.1.2' do
  impact 1.0
  title 'Disable System on Audit Log Full'
  desc "In high security contexts, the risk of detecting unauthorized access or nonrepudiation
        exceeds the benefit of the system's availability."
  tag logging: 'audit'

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^space_left_action\s+=\s+email/) }
    its('content') { should match(/^action_mail_acct\s+=\s+root/) }
    its('content') { should match(/^admin_space_left_action\s+=\s+halt/) }
  end
end

# TODO: determine common configs and test present
control 'cis-logging-5.2.1.3' do
  impact 1.0
  title 'Keep All Auditing Information'
  desc "In high security contexts, the benefits of maintaining a long audit history exceed the cost of
        storing the audit history."
  tag logging: 'audit'

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/max_log_file_action\s+=\s+keep_logs/) }
  end
end

control 'cis-logging-5.2.2' do
  impact 1.0
  title 'Enable auditd service'
  desc "The capturing of system events provides system administrators with information to allow
        them to determine if unauthorized access to their system is occurring."
  tag logging: 'audit'

  describe service('auditd') do
    it { should be_enabled }
  end
end

control 'cis-logging-5.2.3' do
  impact 1.0
  title 'Enable Auditing for Processes That Start Prior to auditd'
  desc "Audit events need to be captured on processes that start up prior to auditd, so that
        potential malicious activity cannot go undetected."
  tag logging: 'audit'

  describe file('/boot/grub2/grub.cfg') do
    its('content') { should match(/\s+linux.*audit=1/) }
  end
  describe file('/etc/default/grub') do
    its('content') { should match(/^GRUB_CMDLINE_LINUX=.*audit=1/) }
  end
end

control 'cis-logging-5.2.4' do
  impact 1.0
  title 'Record Events That Modify Date and Time Information'
  desc "Unexpected changes in system date and/or time could be a sign of malicious activity on the
        system."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change/) }
    its('content') { should match(/-a always,exit -F arch=b64 -S clock_settime -k time-change/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S clock_settime -k time-change/) }
    its('content') { should match(%r{-w /etc/localtime -p wa -k time-change}) }
  end
end

control 'cis-logging-5.2.5' do
  impact 1.0
  title 'Record Events That Modify User/Group Information'
  desc "Unexpected changes to these files could be an indication that the system has been
        compromised and that an unauthorized user is attempting to hide their activities or
        compromise additional accounts."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /etc/group -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/passwd -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/gshadow -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/shadow -p wa -k identity}) }
    its('content') { should match(%r{-w /etc/security/opasswd -p wa -k identity}) }
  end
end

control 'cis-logging-5.2.6' do
  impact 1.0
  title "Record Events That Modify the System's Network Environment"
  desc 'Monitoring sethostname and setdomainname will identify potential unauthorized changes
       to host and domainname of a system. The changing of these names could potentially break
       security parameters that are set based on those names. The /etc/hosts file is monitored
       for changes in the file that can indicate an unauthorized intruder is trying to change
       machine associations with IP addresses and trick users and processes into connecting to
       unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as
       intruders could put disinformation into those files and trick users into providing
       information to the intruder. Monitoring /etc/sysconfig/network is important as it can
       show if network interfaces or scripts are being modified in a way that can lead to the
       machine becoming unavailable or compromised. All audit records will be tagged with the
       identifier "system-locale."'
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale/) }
    its('content') { should match(%r{-w /etc/issue -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/issue.net -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/hosts -p wa -k system-locale}) }
    its('content') { should match(%r{-w /etc/sysconfig/network -p wa -k system-locale}) }
  end
end

control 'cis-logging-5.2.7' do
  impact 1.0
  title "Record Events That Modify the System's Mandatory Access Controls"
  desc "Changes to files in this directory could indicate that an unauthorized user is attempting to
        modify access controls and change security contexts, leading to a compromise of the
        system."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /etc/selinux/ -p wa -k MAC-policy}) }
  end
end

control 'cis-logging-5.2.8' do
  impact 1.0
  title 'Collect Login and Logout Events'
  desc "Monitoring login/logout events could provide a system administrator with information
        associated with brute force attacks against user logins."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /var/log/faillog -p wa -k logins}) }
    its('content') { should match(%r{-w /var/log/lastlog -p wa -k logins}) }
    its('content') { should match(%r{-w /var/log/tallylog -p wa -k logins}) }
  end
end

control 'cis-logging-5.2.9' do
  impact 1.0
  title 'Collect Session Initiation Information'
  desc "Monitoring these files for changes could alert a system administrator to logins occurring at
        unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when
        they do not normally log in)."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /var/run/utmp -p wa -k session}) }
    its('content') { should match(%r{-w /var/log/wtmp -p wa -k session}) }
    its('content') { should match(%r{-w /var/log/btmp -p wa -k session}) }
  end
end

control 'cis-logging-5.2.10' do
  impact 1.0
  title 'Collect Discretionary Access Control Permission Modification Events'
  desc "Monitoring for changes in file attributes could alert a system administrator to activity that
        could indicate intruder activity or policy violation."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
    its('content') { should match(/-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
    its('content') { should match(/-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod/) }
  end
end

control 'cis-logging-5.2.11' do
  impact 1.0
  title 'Collect Unsuccessful Unauthorized Access Attempts to Files'
  desc "Failed attempts to open, create or truncate files could be an indication that an individual or
        process is trying to gain unauthorized access to the system."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access/) }
    its('content') { should match(/-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access/) }
  end
end

control 'cis-logging-5.2.12' do
  impact 1.0
  title 'Collect Use of Privileged Commands'
  desc "Execution of privileged commands by non-privileged users could be an indication of
        someone trying to gain unauthorized access to the system."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
    its('content') { should match(%r{-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged}) }
  end
end

control 'cis-logging-5.2.13' do
  impact 1.0
  title 'Collect Successful File System Mounts'
  desc "It is highly unusual for a non privileged user to mount file systems to the system. While
        tracking mount commands gives the system administrator evidence that external media
        may have been mounted (based on a review of the source of the mount and confirming it's
        an external media type), it does not conclusively indicate that data was exported to the
        media. System administrators who wish to determine if data were exported, would also
        have to track successful open, creat and truncate system calls requiring write access to a
        file under the mount point of the external media file system. This could give a fair
        indication that a write occurred. The only way to truly prove it, would be to track
        successful writes to the external media. Tracking write system calls could quickly fill up the
        audit log and is not recommended. Recommendations on configuration options to track
        data export to media is beyond the scope of this document.
        Note: This tracks successful and unsuccessful mount commands. File system mounts do not
        have to come from external media and this action still does not verify write (e.g. CD ROMS)"
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts/) }
  end
end

control 'cis-logging-5.2.14' do
  impact 1.0
  title 'Collect File Deletion Events by User'
  desc "Monitoring these calls from non-privileged users could provide a system administrator
        with evidence that inappropriate removal of files and file attributes associated with
        protected files is occurring. While this audit option will look at all events, system
        administrators will want to look for specific privileged files that are being deleted or
        altered."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete/) }
    its('content') { should match(/-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete/) }
  end
end

control 'cis-logging-5.2.15' do
  impact 1.0
  title 'Collect Changes to System Administration Scope'
  desc "Changes in the /etc/sudoers file can indicate that an unauthorized change has been made
        to scope of system administrator activity."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /etc/sudoers -p wa -k scope}) }
  end
end

control 'cis-logging-5.2.16' do
  impact 1.0
  title 'Collect System Administrator Actions (sudolog)'
  desc "Changes in /var/log/sudo.log indicate that an administrator has executed a command or
        the log file itself has been tampered with. Administrators will want to correlate the events
        written to the audit trail with the records written to /var/log/sudo.log to verify if
        unauthorized commands have been executed."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /var/log/sudo.log -p wa -k actions}) }
  end
end

control 'cis-logging-5.2.17' do
  impact 1.0
  title 'Collect Kernel Module Loading and Unloading'
  desc "Monitoring the use of insmod, rmmod and modprobe could provide system administrators
        with evidence that an unauthorized user loaded or unloaded a kernel module, possibly
        compromising the security of the system. Monitoring of the init_module and
        delete_module system calls would reflect an unauthorized user attempting to use a
        different program to load and unload modules."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(%r{-w /sbin/insmod -p x -k modules}) }
    its('content') { should match(%r{-w /sbin/rmmod -p x -k modules}) }
    its('content') { should match(%r{-w /sbin/modprobe -p x -k modules}) }
    its('content') { should match(/-a always,exit -F arch=b64 -S init_module -S delete_module -k modules/) }
  end
end

control 'cis-logging-5.2.18' do
  impact 1.0
  title 'Make the Audit Configuration Immutable'
  desc "In immutable mode, unauthorized users cannot execute changes to the audit system to
        potential hide malicious activity and then put the audit rules back. Users would most likely
        notice a system reboot and that could alert administrators of an attempt to make
        unauthorized audit changes."
  tag logging: 'audit'

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^-e 2/) }
  end
end
