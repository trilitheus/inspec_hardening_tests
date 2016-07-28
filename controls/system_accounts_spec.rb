control 'cis-services-7.2' do
  impact 1.0
  title 'Disable System Accounts'
  desc "It is important to make sure that accounts that are not being used by regular users are
        locked to prevent them from being used to provide an interactive shell. By default, Red Hat
        sets the password field for these accounts to an invalid string, but it is also recommended
        that the shell field in the password file be set to /sbin/nologin. This prevents the account
        from potentially being used to run any commands."
  tag config: 'accounts'

  accounts = command('egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" &&
                                                             $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}\'')
  describe accounts do
    its('stdout') { should eq '' }
  end
end
