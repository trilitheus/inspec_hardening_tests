## This is an invalid test as /etc/grub.cfg does not exist in RHEL7 family
# control 'cis-selinux-1.4.1' do
# impact 1.0
# title 'Enable SELinux in /etc/grub.conf'
# desc "SELinux must be enabled at boot time in /etc/grub.conf to ensure that the controls it
#       provides are not overwritten.
# tag selinux: 'file'
# end

control 'cis-selinux-1.4.2' do
  impact 1.0
  title 'Set the SELinux State'
  desc "SELinux must be enabled at boot time in to ensure that the controls it provides are in effect
        at all times."
  tag selinux: 'file'

  describe file('/etc/selinux/config') do
    its('content') { should match(/SELINUX=enforcing/) }
  end

  get_selinux = command('/sbin/sestatus')
  describe get_selinux do
    its('stdout') { should match(/SELinux\sstatus:\s+enabled/) }
  end
end

control 'cis-selinux-1.4.3' do
  impact 1.0
  title 'Set the SELinux Policy'
  desc "Security configuration requirements vary from site to site. Some sites may mandate a
        policy that is stricter than the default policy, which is perfectly acceptable. This item is
        intended to ensure that at least the default recommendations are met."

  describe file('/etc/selinux/config') do
    its('content') { should match(/SELINUXTYPE=targeted/) }
  end

  get_selinux = command('/sbin/sestatus')
  describe get_selinux do
    its('stdout') { should match(/Loaded\spolicy\sname:\s+targeted/) }
  end
end

control 'cis-selinux-1.4.4' do
  impact 0.1
  title 'Remove SETroubleshoot'
  desc "The SETroubleshoot service is an unnecessary daemon to have running on a server,
        especially if X Windows is disabled."

  describe package('setroubleshoot') do
    it { should_not be_installed }
  end
end

control 'cis-selinux-1.4.5' do
  impact 0.1
  title 'Remove MCS Translation Service (mcstrans)'
  desc "Since this service is not used very often, disable it to reduce the amount of potentially
        vulnerable code running on the system."

  describe package('mcstrans') do
    it { should_not be_installed }
  end
end

control 'cis-selinux-1.4.6' do
  impact 0.5
  title 'Check for Unconfined Daemons'
  desc "Since daemons are launched and descend from the init process, they will inherit the
        security context label initrc_t. This could cause the unintended consequence of giving the
        process more permission than it requires."

  unconfined = command('ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr \':\' \' \' | awk \'{ print $NF }\')')
  describe unconfined do
    its('stdout') { should eq '' }
  end
end
