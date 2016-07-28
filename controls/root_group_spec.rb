control 'cis-services-7.3' do
  impact 1.0
  title 'Set Defalt Group for root Account'
  desc "Using GID 0 for the root account helps prevent root-owned files from accidentally
        becoming accessible to non-privileged users."
  tag config: 'accounts'

  root_group = command('grep "^root:" /etc/passwd | cut -f4 -d:')
  describe root_group do
    its('stdout') { should match(/^0$/) }
  end
end
