control 'cis-login-6.4' do
  impact 1.0
  title 'Restrict root Login to System Console'
  desc "Since the system console has special properties to handle emergency situations, it is
        important to ensure that the console is in a physically secure location and that
        unauthorized consoles have not been defined."
  tag config: 'securetty'

  describe file('/etc/securetty') do
    its('content') { should match(/\Atty1\ntty2\ntty3\ntty4\ntty5\ntty6\ntty7\ntty8\ntty9\ntty10\ntty11\nttyS0\Z/) }
  end
end
