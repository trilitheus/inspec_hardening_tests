control 'cis-services-6.3.1' do
  impact 1.0
  title 'Upgrade Password Hashing Algorithm to SHA-512'
  desc "The SHA-512 algorithm provides much stronger hashing than MD5, thus providing
        additional protection to the system by increasing the level of effort for an attacker to
        successfully determine passwords."
  tag config: 'pam'

  hash = command('authconfig --test | grep hashing')
  describe hash do
    its('stdout') { should match(/sha512/) }
  end
end

control 'cis-services-6.3.2' do
  impact 1.0
  title 'Set Password Creation Requirement Parameters Using pam_cracklib'
  desc 'Strong passwords protect systems from being hacked through brute force methods.'
  tag config: 'pam'

  describe file('/etc/pam.d/system-auth-ac') do
    its('content') { should match(/password\s+requisite\s+pam_cracklib.so\s+try_first_pass\s+retry=3\s+minlen=14\s+dcredit=-1\s+ucredit=-1\s+ocredit=-1\s+lcredit=-1/) }
  end
end

control 'cis-services-6.3.3' do
  impact 1.0
  title 'Set Lockout for Failed Password Attempts'
  desc "Locking out userIDs after n unsuccessful consecutive login attempts mitigates brute force
        password attacks against your systems."
  tag config: 'pam'

  describe file('/etc/pam.d/system-auth-ac') do
    its('content') { should match(/deny=5/) }
  end
  describe file('/etc/pam.d/password-auth-ac') do
    its('content') { should match(/deny=5/) }
  end
end

control 'cis-services-6.3.4' do
  impact 1.0
  title 'Limit Password Reuse'
  desc "Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be
        able to guess the password.
        Note that these change only apply to accounts configured on the local system.
        Note that we increase this requirement to 24 past passwords"
  tag config: 'pam'

  describe file('/etc/pam.d/system-auth-ac') do
    its('content') { should match(/remember=24/) }
  end
end

control 'cis-login-6.5' do
  impact 1.0
  title 'Restrict Access to the su Command'
  desc "Restricting the use of su, and using sudo in its place, provides system administrators better
        control of the escalation of user privileges to execute privileged commands. The sudo utility
        also provides a better logging and audit mechanism, as it can log each command executed
        via sudo, whereas su can only record that a user executed the su program."
  tag config: 'su'

  describe file('/etc/pam.d/su') do
    its('content') { should match(/^auth\s+required\s+pam_wheel.so\s+use_uid$/) }
  end
end
