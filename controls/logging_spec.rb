control 'cis-logging-5.1.1' do
  impact 1.0
  title 'Install the rsyslog package'
  desc "The security enhancements of rsyslog such as connection-oriented (i.e. TCP) transmission
        of logs, the option to log to database formats, and the encryption of log data en route to a
        central logging server) justify installing and configuring the package."
  tag logging: 'rsyslog'

  describe package('rsyslog') do
    it { should be_installed }
  end
end

control 'cis-logging-5.1.2' do
  impact 1.0
  title 'Activate the rsyslog Service'
  desc 'If the rsyslog service is not activated the system will not have a syslog service running.'
  tag logging: 'rsyslog'

  describe service('rsyslog') do
    it { should be_enabled }
  end
end

# TODO: determine common configs and test present
control 'cis-logging-5.1.3' do
  impact 1.0
  title 'Configure /etc/rsyslog.conf'
  desc "A great deal of important security-related information is sent via rsyslog (e.g., successful
        and failed su attempts, failed login attempts, root login attempts, etc.)."
  tag logging: 'rsyslog'

  describe file('/etc/rsyslog.conf') do
    its('content') { should match(/auth/) }
  end
end

control 'cis-logging-5.1.4' do
  impact 1.0
  title 'Create and Set Permissions on rsyslog Log Files'
  desc "It is important to ensure that log files exist and have the correct permissions to ensure that
        sensitive rsyslog data is archived and protected."
  tag logging: 'rsyslog'
  # TODO: Add a test
end

control 'cis-logging-5.1.5' do
  impact 1.0
  title 'Configure rsyslog to Send Logs to a Remote Log Host'
  desc "Storing log data on a remote host protects log integrity from local attacks. If an attacker
        gains root access on the local system, they could tamper with or remove log data that is
        stored on the local system"
  tag logging: 'rsyslog'
  # TODO: Add a test
end

control 'cis-logging-5.1.6' do
  impact 1.0
  title 'Accept Remote rsyslog Messages Only on Designated Log Hosts'
  desc "The guidance in the section ensures that remote log hosts are configured to only accept
        rsyslog data from hosts within the specified domain and that those systems that are not
        designed to be log hosts do not accept any remote rsyslog messages. This provides
        protection from spoofed log data and ensures that system administrators are reviewing
        reasonably complete syslog data in a central location."
  tag logging: 'rsyslog'
  # TODO: Add a test
end
