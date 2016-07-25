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

  describe file('/etc/grub2/grub.cfg') do
    its('content') { should match(/\s+linux.*audit=1/) }
  end
end
