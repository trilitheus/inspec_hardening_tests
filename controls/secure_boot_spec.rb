control 'cis-boot-1.5.1' do
  impact 1.0
  title 'Set User/Group Owner on /boot/grub2/grub.cfg'
  desc 'Setting the owner and group to root prevents non-root users from changing the file.'
  tag boot: 'file'

  describe file('/boot/grub2/grub.cfg') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-boot-1.5.2' do
  impact 1.0
  title 'Set Permissions on /boot/grub2/grub.cfg'
  desc "Setting the permissions to read and write for root only prevents non-root users from
        seeing the boot parameters or changing them. Non-root users who read the boot
        parameters may be able to identify weaknesses in security upon boot and be able to exploit
        them."
  tag boot: 'file'

  describe file('/boot/grub2/grub.cfg') do
    its('mode') { should eq 0644 }
  end
end

control 'cis-boot-1.5.3' do
  impact 1.0
  title ' Set Boot Loader Password'
  desc "Requiring a boot password upon execution of the boot loader will prevent an unauthorized
        user from entering boot parameters or changing the boot partition. This prevents users
        from weakening security (e.g. turning off SELinux at boot time)."

  tag boot: 'password'
end
