control 'cis-sw-1.2.1' do
  impact 1.0
  title 'Configure Connection to the RHN RPM Repositories'
  desc "It is important to register with the Red Hat Network to make sure that patches are updated
        on a regular basis. This helps to reduce the exposure time as new vulnerabilities are
        discovered."
  tag software: 'rhn'
end

control 'cis-sw-1.2.2' do
  impact 1.0
  title 'Verify Red Hat/CentOS GPG Key is Installed'
  desc "It is important to ensure that updates are obtained from a valid source to protect against
        spoofing that could lead to the inadvertent installation of malware on the system."
  tag software: 'gpg'

  check_centos_gpg = command('rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep CentOS-7')

  describe check_centos_gpg do
    its('exit_status') { should eq 0 }
  end
end

control 'cis-sw-1.2.3' do
  impact 1.0
  title 'Verify that gpgcheck is Globally Activated'
  desc "It is important to ensure that an RPM's package signature is always checked prior to
        installation to ensure that the software is obtained from a trusted source."
  tag software: 'gpg'

  describe file('/etc/yum.conf') do
    its('content') { should match(/gpgcheck=1/) }
  end
end

control 'cis-sw-1.2.4' do
  impact 0.1
  title 'Disable the rhnsd Daemon'
  desc "Patch management policies may require that organizations test the impact of a patch
        before it is deployed in a production environment. Having patches automatically deployed
        could have a negative impact on the environment. It is best to not allow an action by default
        but only after appropriate consideration has been made. It is recommended that the service
        be disabled unless the risk is understood and accepted or you are running your own
        satellite . This item is not scored because organizations may have addressed the risk."
  tag software: 'rhn'
end

control 'cis-sw-1.2.5' do
  impact 0.1
  title 'Obtain Software Package Updates with yum'
  desc "The yum update utility is the preferred method to update software since it checks for
        dependencies and ensures that the software is installed correctly. Refer to your local patch
        management procedures for the method used to perform yum updates."

  check_updates = command('yum update --assumeno')

  describe check_updates do
    its('stdout') { should match(/No packages marked for update/) }
  end
end

control 'cis-sw-1.2.6' do
  impact 0.5
  title 'Verify Package Integrity Using RPM'
  desc "Verifying packages gives a system administrator the ability to detect if package files were
        changed, which could indicate that a valid binary was overwritten with a trojaned binary."

  verify_rpms = command('rpm -qVa | awk \'$2 != "c" { print $0}\'')

  describe verify_rpms do
    its('stdout') { should eq '' }
  end
end
