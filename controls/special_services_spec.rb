control 'cis-services-3.1' do
  impact 1.0
  title 'Set Daemon umask'
  desc "Setting the umask to 027 will make sure that files created by daemons will not be readable,
        writable or executable by any other than the group and owner of the daemon process and
        will not be writable by the group of the daemon process. The daemon process can manually
        override these settings if these files need additional permission."
  tag services: 'umask'

  describe file('/etc/sysconfig/init') do
    its('content') { should match(/^umask\s+027/) }
  end
end

control 'cis-services-3.2' do
  impact 1.0
  title 'Remove the X Windows System'
  desc "Unless your organization specifically requires graphical login access via the X Window
        System, remove the server to reduce the potential attack surface."
  tag services: 'x11'

  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end

  default_target = command('systemctl get-default')
  describe default_target do
    its('stdout') { should match(/multi-user.target/) }
  end
end

control 'cis-services-3.3' do
  impact 1.0
  title 'Disable Avahi Server'
  desc "Since servers are not normally used for printing, this service is not needed unless
        dependencies require it. If this is the case, disable the service to reduce the potential attack
        surface. If for some reason the service is required on the server, follow the
        recommendations in sub-sections 3.2.1 - 3.2.5 to secure it."
  tag services: 'avahi'

  describe service('avahi-daemon') do
    it { should_not be_enabled }
  end
end

control 'cis-services-3.4' do
  impact 1.0
  title 'Disable Print Server - CUPS'
  desc "If the system does not need to print jobs or accept print jobs from other systems, it is
        recommended that CUPS be disabled to reduce the potential attack surface."
  tag services: 'cups'

  describe service('cups') do
    it { should_not be_enabled }
  end
end

control 'cis-services-3.5' do
  impact 1.0
  title 'Remove DHCP Server'
  desc "Unless a server is specifically set up to act as a DHCP server, it is recommended that this
        service be deleted to reduce the potential attack surface."
  tag services: 'dhcp'

  describe package('dhcp') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.6' do
  impact 1.0
  title 'TODO: Configure NTP'
  desc "It is recommended that physical systems and virtual guests lacking direct access to the
        physical host's clock be configured as NTP clients to synchronize their clocks (especially to
        support time sensitive security mechanisms like Kerberos). This also ensures log files have
        consistent time records across the enterprise, which aids in forensic investigations."
  tag services: 'ntp'
end

control 'cis-services-3.7' do
  impact 1.0
  title 'Remove LDAP'
  desc "If the server will not need to act as an LDAP client or server, it is recommended that the
        software be disabled to reduce the potential attack surface."
  tag services: 'ldap'

  describe package('openldap-servers') do
    it { should_not be_installed }
  end

  describe package('openldap-clients') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.8' do
  impact 1.0
  title 'Disable NFS and RPC'
  desc "If the server does not export NFS shares or act as an NFS client, it is recommended that
        these services be disabled to reduce remote attack surface."
  tag services: 'nfs'

  describe service('nfslock') do
    it { should_not be_enabled }
  end
  describe service('rpcgssd') do
    it { should_not be_enabled }
  end
  describe service('rpcbind') do
    it { should_not be_enabled }
  end
  describe service('rpcidmapd') do
    it { should_not be_enabled }
  end
  describe service('rpcsvcgssd') do
    it { should_not be_enabled }
  end
end

control 'cis-services-3.9' do
  impact 1.0
  title 'Remove DNS Server'
  desc "Unless a server is specifically designated to act as a DNS server, it is recommended that the
        package be deleted to reduce the potential attack surface."
  tag services: 'dns'

  describe package('bind') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.10' do
  impact 1.0
  title 'Remove FTP Server'
  desc "FTP does not protect the confidentiality of data or authentication credentials. It is
        recommended sftp be used if file transfer is required. Unless there is a need to run the
        system as a FTP server (for example, to allow anonymous downloads), it is recommended
        that the package be deleted to reduce the potential attack surface."
  tag services: 'ftp'

  describe package('vsftp') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.11' do
  impact 1.0
  title 'Remove HTTP Server'
  desc "Unless there is a need to run the system as a web server, it is recommended that the
        package be deleted to reduce the potential attack surface."
  tag services: 'http'

  describe package('httpd') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.12' do
  impact 1.0
  title 'Remove Dovecot (IMAP and POP3 services)'
  desc "Unless POP3 and/or IMAP servers are to be provided to this server, it is recommended that
        the service be deleted to reduce the potential attack surface."
  tag services: 'mail'

  describe package('dovecot') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.13' do
  impact 1.0
  title 'Remove Samba'
  desc "If there is no need to mount directories and file systems to Windows systems, then this
        service can be deleted to reduce the potential attack surface."
  tag services: 'samba'

  describe package('samba') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.14' do
  impact 1.0
  title 'Remove HTTP Proxy Server'
  desc "If there is no need for a proxy server, it is recommended that the squid proxy be deleted to
        reduce the potential attack surface."
  tag services: 'squid'

  describe package('squid') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.15' do
  impact 1.0
  title 'Remove SNMP Server'
  desc "The SNMP server communicates using SNMP v1, which transmits data in the clear and does
        not require authentication to execute commands. Unless absolutely necessary, it is
        recommended that the SNMP service not be used."
  tag services: 'snmp'

  describe package('net-snmp') do
    it { should_not be_installed }
  end
end

control 'cis-services-3.16' do
  impact 1.0
  title 'Configure Mail Transfer Agent for Local-Only Mode'
  desc "The software for all Mail Transfer Agents is complex and most have a long history of
        security issues. While it is important to ensure that the system can process local mail
        messages, it is not necessary to have the MTA's daemon listening on a port unless the
        server is intended to be a mail server that receives and processes mail from other systems"
  tag services: 'mail'

  check_ports = command('netstat -an | grep LIST | grep ":25[[:space:]]"')
  describe check_ports do
    its('stdout') { should match(/tcp\s+0\s+0\s+127.0.0.1:25\s+0.0.0.0:\*\s+LISTEN/) }
  end
end
