control 'cis-additional-1.6.1' do
  impact 1.0
  title 'Restrict Core Dumps'
  desc "Setting a hard limit on core dumps prevents users from overriding the soft variable. If core
        dumps are required, consider setting limits for user groups (see limits.conf(5)). In
        addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from
        dumping core."

  describe file('/etc/security/limits.conf') do
    its('content') { should match(/\*\s+hard\s+core\s+0/) }
  end
  describe file('/etc/sysctl.conf') do
    its('content') { should match(/fs.suid_dumpable\s+=\s+0/) }
  end
end

control 'cis-additional-1.6.2' do
  impact 1.0
  title 'Enable Randomized Virtual Memory Region Placement'
  desc "Randomly placing virtual memory regions will make it difficult for to write memory page
        exploits as the memory placement will be consistently shifting"

  describe file('/etc/sysctl.conf') do
    its('content') { should match(/kernel.randomize_va_space\s+=\s+2/) }
  end
end
