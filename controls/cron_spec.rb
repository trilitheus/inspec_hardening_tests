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
