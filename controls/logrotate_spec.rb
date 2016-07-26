control 'cis-aide-5.3' do
  impact 1.0
  title 'Configure logrotate'
  desc "By keeping the log files smaller and more manageable, a system administrator can easily
        archive these files to another system and spend less time looking through inordinately
        large log files."
  tag logging: 'logrotate'

  describe file('/etc/logrotate.conf') do
    its('content') { should match(%r{^/var/log/wtmp}) }
    its('content') { should match(%r{^/var/log/btmp}) }
  end
  describe file('/etc/logrotate.d/syslog') do
    its('content') { should match(%r{^/var/log/cron}) }
    its('content') { should match(%r{^/var/log/maillog}) }
    its('content') { should match(%r{^/var/log/messages}) }
    its('content') { should match(%r{^/var/log/secure}) }
    its('content') { should match(%r{^/var/log/spooler}) }
  end
  describe file('/etc/logrotate.d/aide') do
    its('content') { should match(%r{^/var/log/aide/\*.log}) }
  end
  describe file('/etc/logrotate.d/yum') do
    its('content') { should match(%r{^/var/log/yum.log}) }
  end
end
