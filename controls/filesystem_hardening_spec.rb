control 'cis-fs-1.1.1' do
  impact 1.0
  title 'Filesystem: Create separate partition for /tmp'
  desc "Since the /tmp directory is intended to be world-writable, there is a risk of resource
        exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file
        system allows an administrator to set the noexec option on the mount, making /tmp
        useless for an attacker to install executable code. It would also prevent an attacker from
        establishing a hardlink to a system setuid program and wait for it to be updated. Once the
        program was updated, the hardlink would be broken and the attacker would have his own
        copy of the program. If the program happened to have a security vulnerability, the attacker
        could continue to exploit the known flaw."
  tag filesystem: '/tmp'

  describe file('/tmp') do
    it { should be_mounted }
  end
end

control 'cis-fs-1.1.2' do
  impact 1.0
  title 'Filesystem: Set nodev option for /tmp'
  desc "Since the /tmp filesystem is not intended to support devices, set this option to ensure that
        users cannot attempt to create block or character special devices in /tmp."
  tag filesystem: '/tmp'

  describe file('/etc/fstab') do
    its('content') { should match %r{.*/tmp.*nodev.*} }
  end
  describe mount('/tmp') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-fs-1.1.3' do
  impact 1.0
  title 'Filesystem: Set nosuid option for /tmp'
  desc "Since the /tmp filesystem is only intended for temporary file storage, set this option to
        ensure that users cannot create set userid files in /tmp."
  tag filesystem: '/tmp'

  describe file('/etc/fstab') do
    its('content') { should match %r{.*/tmp.*nosuid.*} }
  end
  describe mount('/tmp') do
    its('options') { should include 'nosuid' }
  end
end

control 'cis-fs-1.1.4' do
  impact 1.0
  title 'Filesystem: Set noexec option for /tmp'
  desc "Since the /tmp filesystem is only intended for temporary file storage, set this option to
        ensure that users cannot run executable binaries from /tmp."
  tag filesystem: '/tmp'

  describe file('/etc/fstab') do
    its('content') { should match %r{.*/tmp.*noexec.*} }
  end
  describe mount('/tmp') do
    its('options') { should include 'noexec' }
  end
end

control 'cis-fs-1.1.5' do
  impact 1.0
  title 'Filesystem: Create separate partition for /var'
  desc "Since the /var directory may contain world-writable files and directories, there is a risk of
        resource exhaustion if it is not bound to a separate partition."
  tag filesystem: '/var'

  describe file('/var') do
    it { should be_mounted }
  end
end

# control 'cis-fs-1.1.6' do
#   title 'Filesystem: Bind Mount the /var/tmp directory to /tmp'

control 'cis-fs-1.1.7' do
  impact 1.0
  title 'Filesystem: Create separate partition for /var/log'
  desc "There are two important reasons to ensure that system logs are stored on a separate
        partition: protection against resource exhaustion (since logs can grow quite large) and
        protection of audit data."
  tag filesystem: '/var/log'

  describe file('/var/log') do
    it { should be_mounted }
  end
end

control 'cis-fs-1.1.8' do
  impact 1.0
  title 'Filesystem: Create separate partition for /var/log/audit'
  desc "There are two important reasons to ensure that data gathered by auditd is stored on a
        separate partition: protection against resource exhaustion (since the audit.log file can
        grow quite large) and protection of audit data. The audit daemon calculates how much free
        space is left and performs actions based on the results. If other processes (such as syslog)
        consume space in the same partition as auditd, it may not perform as desired"
  tag filesystem: '/var/log/audit'

  describe file('/var/log/audit') do
    it { should be_mounted }
  end
end

control 'cis-fs-1.1.9' do
  impact 1.0
  title 'Filesystem: Create separate partition for /home'
  desc "If the system is intended to support local users, create a separate partition for the /home
        directory to protect against resource exhaustion and restrict the type of files that can be
        stored under /home."
  tag filesystem: '/home'

  describe file('/home') do
    it { should be_mounted }
  end
end

control 'cis-fs-1.1.10' do
  impact 1.0
  title 'Filesystem: Set nodev option for /home'
  desc "Since the user partitions are not intended to support devices, set this option to ensure that
        users cannot attempt to create block or character special devices."
  tag filesystem: '/home'

  describe file('/etc/fstab') do
    its('content') { should match %r{.*/home.*nodev.*} }
  end
  describe mount('/home') do
    its('options') { should include 'nodev' }
  end
end

# control 'cis-fs-1.1.11' do
#  title 'Filesystem: Add nodev Option to Removable Media Partitions'

# control 'cis-fs-1.1.12' do
#  title 'Filesystem: Add noexec Option to Removable Media Partitions'

# control 'cis-fs-1.1.13' do
#  title 'Filesystem: Add nosuid Option to Removable Media Partitions'

# control 'cis-fs-1.1.14' do
#  title 'Filesystem: Add nodev Option to /dev/shm Partition'

# control 'cis-fs-1.1.15' do
#  title 'Filesystem: Add nosuid Option to /dev/shm Partition'

# control 'cis-fs-1.1.16' do
#  title 'Filesystem: Add noexec Option to /dev/shm Partition'

control 'cis-fs-1.1.17' do
  impact 1.0
  title 'Set Sticky Bit on All World-Writable Directories'
  desc "This feature prevents the ability to delete or rename files in world writable directories
        (such as /tmp) that are owned by another user."
  tag filesystem: 'global'

  check_sticky_bit = command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)")
  describe check_sticky_bit do
    its('stdout') { should eq '' }
  end
end

control 'cis-fs-1.1.18' do
  impact 0.1
  title 'Disable Mounting of cramfs Filesystems'
  desc "Removing support for unneeded filesystem types reduces the local attack surface of the
        server. If this filesystem type is not needed, disable it."
  tag kernel: 'cramfs'

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
  end
  check_cramfs = command('/sbin/modprobe -n -v cramfs')
  describe check_cramfs do
    its('stdout') { should match %r{install /bin/true} }
  end
end

# control 'cis-fs-1.1.19' do
#  title 'Disable Mounting of freevxfs Filesystems'

# control 'cis-fs-1.1.20' do
#  title 'Disable Mounting of jffs2 Filesystems'

# control 'cis-fs-1.1.21' do
#  title 'Disable Mounting of hfs Filesystems'

# control 'cis-fs-1.1.22' do
#  title 'Disable Mounting of hfsplus Filesystems'

control 'cis-fs-1.1.23' do
  impact 0.1
  title 'Disable Mounting of squashfs Filesystems'
  desc "Removing support for unneeded filesystem types reduces the local attack surface of the
        server. If this filesystem type is not needed, disable it."
  tag kernel: 'squashfs'

  describe kernel_module('squashfs') do
    it { should_not be_loaded }
  end
  check_squashfs = command('/sbin/modprobe -n -v squashfs')
  describe check_squashfs do
    its('stdout') { should match %r{install /bin/true} }
  end
end

control 'cis-fs-1.1.24' do
  impact 0.1
  title 'Disable Mounting of udf Filesystems'
  desc "Removing support for unneeded filesystem types reduces the local attack surface of the
        server. If this filesystem type is not needed, disable it."
  tag kernel: 'udf'

  describe kernel_module('udf') do
    it { should_not be_loaded }
  end
  check_udf = command('/sbin/modprobe -n -v udf')
  describe check_udf do
    its('stdout') { should match %r{install /bin/true} }
  end
end
