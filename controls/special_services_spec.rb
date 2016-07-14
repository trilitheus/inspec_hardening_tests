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
