control 'cis-cron-6.1.1' do
  impact 1.0
  title 'Enable anacron Daemon'
  desc "Cron jobs may include critical security or administrative functions that need to run on a
        regular basis. Use this daemon on machines that are not up 24x7, or if there are jobs that
        need to be executed after the system has been brought back up after a maintenance
        window."
  tag cron: 'install'

  describe package('cronie-anacron') do
    it { should be_installed }
  end
end

control 'cis-cron-6.1.2' do
  impact 1.0
  title 'Enable crond Daemon'
  desc "While there may not be user jobs that need to be run on the system, the system does have
        maintenance jobs that may include security monitoring that have to run and crond is used
        to execute them."
  tag cron: 'enable'

  describe service('crond') do
    it { should be_enabled }
  end
end

control 'cis-cron-6.1.3' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/anacrontab'
  desc "This file contains information on what system jobs are run by anacron. Write access to
        these files could provide unprivileged users with the ability to elevate their privileges. Read
        access to these files could provide users with the ability to gain insight on system jobs that
        run on the system and could provide them a way to gain unauthorized privileged access."
  tag cron: 'permissions'

  describe file('/etc/anacrontab') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0600 }
  end
end

control 'cis-cron-6.1.4' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/crontab'
  desc "This file contains information on what system jobs are run by cron. Write access to these
        files could provide unprivileged users with the ability to elevate their privileges. Read
        access to these files could provide users with the ability to gain insight on system jobs that
        run on the system and could provide them a way to gain unauthorized privileged access."
  tag cron: 'permissions'

  describe file('/etc/crontab') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0600 }
  end
end

control 'cis-cron-6.1.5' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/cron.hourly'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means for gaining unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls."
  tag cron: 'permissions'

  describe file('/etc/cron.hourly') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0700 }
  end
end

control 'cis-cron-6.1.6' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/cron.daily'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means for gaining unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls."
  tag cron: 'permissions'

  describe file('/etc/cron.daily') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0700 }
  end
end

control 'cis-cron-6.1.7' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/cron.weekly'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means for gaining unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls."
  tag cron: 'permissions'

  describe file('/etc/cron.weekly') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0700 }
  end
end

control 'cis-cron-6.1.8' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/cron.monthly'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means for gaining unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls."
  tag cron: 'permissions'

  describe file('/etc/cron.monthly') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0700 }
  end
end

control 'cis-cron-6.1.9' do
  impact 1.0
  title 'Set User/Group Owner and Permission on /etc/cron.d'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means for gaining unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls."
  tag cron: 'permissions'

  describe file('/etc/cron.d') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0700 }
  end
end

control 'cis-cron-6.1.10' do
  impact 1.0
  title 'Restrict at Daemon'
  desc "Granting write access to this directory for non-privileged users could provide them the
        means to gain unauthorized elevated privileges. Granting read access to this directory
        could give an unprivileged user insight in how to gain elevated privileges or circumvent
        auditing controls. In addition, it is a better practice to create a white list of users who can
        execute at jobs versus a blacklist of users who can't execute at jobs as a system
        administrator will always know who can create jobs and does not have to worry about
        remembering to add a user to the blacklist when a new user id is created."
  tag cron: 'permissions'

  describe file('/etc/at.allow') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0400 }
    its('content') { should eq '' }
  end

  describe file('/etc/at.deny') do
    it { should_not exist }
  end
end

control 'cis-cron-6.1.11' do
  impact 1.0
  title 'Restrict at/cron to Authorized Users'
  desc "On many systems, only the system administrator is authorized to schedule cron jobs. Using
        the cron.allow file to control who can run cron jobs enforces this policy. It is easier to
        manage an allow list than a deny list. In a deny list, you could potentially add a user ID to
        the system and forget to add it to the deny files."
  tag cron: 'permissions'

  describe file('/etc/cron.allow') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should eq 0400 }
    its('content') { should eq 'root' }
  end

  describe file('/etc/cron.deny') do
    it { should_not exist }
  end
end
