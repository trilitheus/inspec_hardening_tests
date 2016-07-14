control 'cis-services-2.1.1' do
  impact 1.0
  title 'Remove telnet-server'
  desc "The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission
        medium could allow a user with access to sniff network traffic the ability to steal
        credentials. The ssh package provides an encrypted session and stronger security and is
        included in most Red Hat Linux distributions."
  tag services: 'telnet'

  describe package('telnet-server') do
    it { should_not be_installed }
  end

  describe service('telnetd') do
    it { should_not be_running }
  end
end

control 'cis-services-2.1.2' do
  impact 1.0
  title 'Remove telnet clients'
  desc "The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission
        medium could allow an authorized user to steal credentials. The ssh package provides an
        encrypted session and stronger security and is included in most Red Hat Linux
        distributions."
  tag services: 'telnet'

  describe package('telnet') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.3' do
  impact 1.0
  title 'Remove rsh-server'
  desc "These legacy service contain numerous security exposures and have been replaced with
        the more secure SSH package."
  tag services: 'rsh'

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.4' do
  impact 1.0
  title 'Remove rsh'
  desc "These legacy clients contain numerous security exposures and have been replaced with the
        more secure SSH package. Even if the server is removed, it is best to ensure the clients are
        also removed to prevent users from inadvertently attempting to use these commands and
        therefore exposing their credentials. Note that removing the rsh package removes the
        clients for rsh, rcp and rlogin."
  tag services: 'rsh'

  describe package('rsh') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.5' do
  impact 1.0
  title 'Remove NIS Client'
  desc "The NIS service is inherently an insecure system that has been vulnerable to DOS attacks,
        buffer overflows and has poor authentication for querying NIS maps. NIS generally has
        been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is
        recommended that the service be removed."
  tag services: 'nis'

  describe package('ypbind') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.6' do
  impact 1.0
  title 'Remove NIS Server'
  desc "The NIS service is inherently an insecure system that has been vulnerable to DOS attacks,
        buffer overflows and has poor authentication for querying NIS maps. NIS generally been
        replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is
        recommended that the service be disabled and other, more secure services be used."
  tag services: 'nis'

  describe package('ypserv') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.7' do
  impact 1.0
  title 'Remove tftp'
  desc "It is recommended that TFTP be removed, unless there is a specific need for TFTP (such as
        a boot server). In that case, use extreme caution when configuring the services."
  tag services: 'tftp'

  describe package('tftp') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.8' do
  impact 1.0
  title 'Remove tftp-server'
  desc "TFTP does not support authentication nor does it ensure the confidentiality of integrity of
        data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In
        that case, extreme caution must be used when configuring the services."
  tag services: 'tftp'

  describe package('tftp-server') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.9' do
  impact 1.0
  title 'Remove talk'
  desc 'The software presents a security risk as it uses unencrypted protocols for communication.'
  tag services: 'talk'

  describe package('talk') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.10' do
  impact 1.0
  title 'Remove talk-server'
  desc 'The software presents a security risk as it uses unencrypted protocols for communication.'
  tag services: 'talk'

  describe package('talk-server') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.11' do
  impact 1.0
  title 'Remove xinetd'
  desc "If there are no xinetd services required, it is recommended that the daemon be deleted
        from the system."
  tag services: 'xinetd'

  describe package('xinetd') do
    it { should_not be_installed }
  end
end

control 'cis-services-2.1.12' do
  impact 1.0
  title 'Disable chargen-dgram'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'chargen-dgram'

  describe service('chargen-dgram') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.13' do
  impact 1.0
  title 'Disable chargen-stream'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'chargen-stream'

  describe service('chargen-stream') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.14' do
  impact 1.0
  title 'Disable daytime-dgram'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'daytime-dgram'

  describe service('daytime-dgram') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.15' do
  impact 1.0
  title 'Disable daytime-stream'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'daytime-stream'

  describe service('daytime-stream') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.16' do
  impact 1.0
  title 'Disable echo-dgram'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'echo-dgram'

  describe service('echo-dgram') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.17' do
  impact 1.0
  title 'Disable echo-stream'
  desc 'Disabling this service will reduce the remote attack surface of the system.'
  tag services: 'echo-stream'

  describe service('echo-stream') do
    it { should_not be_enabled }
  end
end

control 'cis-services-2.1.18' do
  impact 1.0
  title 'Disable tcpmux-server'
  desc "tcpmux-server can be abused to circumvent the server's host based firewall. Additionally,
        tcpmux-server can be leveraged by an attacker to effectively port scan the server."
  tag services: 'tcpmux-server'

  describe service('tcpmux-server') do
    it { should_not be_enabled }
  end
end
