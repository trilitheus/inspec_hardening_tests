control 'cis-ssh-6.2.1' do
  impact 1.0
  title 'Set SSH Protocol to 2'
  desc 'SSH v1 suffers from insecurities that do not affect SSH v2.'
  tag config: 'ssh'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('Protocol') { should eq '2' }
  end
end

control 'cis-ssh-6.2.2' do
  impact 1.0
  title 'Set LogLevel to INFO'
  desc "SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically
        not recommended other than strictly for debugging SSH communications since it provides
        so much data that it is difficult to identify important security information. INFO level is the
        basic level that only records login activity of SSH users. In many situations, such as Incident
        Response, it is important to determine when a particular user was active on a system. The
        logout record can eliminate those users who disconnected, which helps narrow the field."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('LogLevel') { should eq 'INFO' }
  end
end

control 'cis-ssh-6.2.3' do
  impact 1.0
  title 'Set Permissions on /etc/ssh/sshd_config'
  desc "The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by nonprivileged
        users, but needs to be readable as this information is used with many nonprivileged
        programs."
  tag config: 'ssh'

  describe file('/etc/ssh/sshd_config') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0600 }
  end
end

control 'cis-ssh-6.2.4' do
  impact 1.0
  title 'Disable SSH X11 Forwarding'
  desc "Disable X11 forwarding unless there is an operational requirement to use X11 applications
        directly. There is a small risk that the remote X11 servers of users who are logged in via
        SSH with X11 forwarding could be compromised by other users on the X11 server. Note
        that even if X11 forwarding is disabled, users can always install their own forwarders."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('X11Forwarding') { should eq 'no' }
  end
end

control 'cis-ssh-6.2.5' do
  impact 1.0
  title 'Set SSH MaxAuthTries to 4 or Less'
  desc "Setting the MaxAuthTries parameter to a low number will minimize the risk of successful
      brute force attacks to the SSH server. While the recommended setting is 4, it is set the
      number based on site policy."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('MaxAuthTries') { should eq '4' }
  end
end

control 'cis-ssh-6.2.6' do
  impact 1.0
  title 'Set SSH IgnoreRhosts to Yes'
  desc 'Setting this parameter forces users to enter a password when authenticating with ssh.'
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('IgnoreRhosts') { should eq 'yes' }
  end
end

control 'cis-ssh-6.2.7' do
  impact 1.0
  title 'Set SSH HostbasedAuthentication to Yes'
  desc "Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf,
        disabling the ability to use .rhosts files in SSH provides an additional layer of protection."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('HostbasedAuthentication') { should eq 'no' }
  end
end

control 'cis-ssh-6.2.8' do
  impact 1.0
  title 'Disable SSH Root Login'
  desc "Disallowing root logins over SSH requires server admins to authenticate using their own
        individual account, then escalating to root via sudo or su. This in turn limits opportunity
        for non-repudiation and provides a clear audit trail in the event of a security incident."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('PermitRootLogin') { should eq 'no' }
  end
end

control 'cis-ssh-6.2.9' do
  impact 1.0
  title 'Set SSH PermitEmptyPasswords to No'
  desc "Disallowing remote shell access to accounts that have an empty password reduces the
        probability of unauthorized access to the system."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
end

control 'cis-ssh-6.2.10' do
  impact 1.0
  title 'Do Not Allow Users to Set Environment Options'
  desc "Permitting users the ability to set environment variables through the SSH daemon could
        potentially allow users to bypass security controls (e.g. setting an execution path that has
        ssh executing trojaned programs)."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

control 'cis-ssh-6.2.11' do
  impact 1.0
  title 'Use Only Approved Cipher in Counter Mode'
  desc "Based on research conducted at various institutions, it was determined that the symmetric
        portion of the SSH Transport Protocol (as described in RFC 4253) has security weaknesses
        that allowed recovery of up to 32 bits of plaintext from a block of ciphertext that was
        encrypted with the Cipher Block Chaining (CBC) method. From that research, new Counter
        mode algorithms (as described in RFC4344) were designed that are not vulnerable to these
        types of attacks and these algorithms are now recommended for standard use."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('Ciphers') { should eq 'aes256-ctr,aes192-ctr,aes128-ctr' }
  end
end

control 'cis-ssh-6.2.12' do
  impact 1.0
  title 'Set Idle Timeout Interval for User Login'
  desc "Having no timeout value associated with a connection could allow an unauthorized user
        access to another user's ssh session (e.g. user walks away from their computer and doesn't
        lock the screen). Setting a timeout value at least reduces the risk of this happening.
        While the recommended setting is 300 seconds (5 minutes), set this timeout value based on
        site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client
        session will be terminated after 5 minutes of idle time and no keepalive messages will be
        sent."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('ClientAliveInterval') { should eq '300' }
    its('ClientAliveCountMax') { should eq '0' }
  end
end

control 'cis-ssh-6.2.13' do
  impact 1.0
  title 'Limit Access via SSH'
  desc "Restricting which users can remotely access the system via SSH will help ensure that only
        authorized users access the system."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('AllowUsers') { should eq 'vagrant' }
  end
end

control 'cis-ssh-6.2.14' do
  impact 1.0
  title 'Set SSH Banner'
  desc "Banners are used to warn connecting users of the particular site's policy regarding
        connection. Consult with your legal department for the appropriate warning banner for
        your site."
  tag config: 'ssh'

  describe ssh_config('/etc/ssh/sshd_config') do
    its('Banner') { should eq '/etc/issue' }
  end
end
