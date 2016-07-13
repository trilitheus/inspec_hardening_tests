control 'cis-aide-1.3.1' do
  impact 1.0
  title 'Install AIDE'
  desc "Install AIDE to make use of the file integrity features to monitor critical files for changes
        that could affect the security of the system."
  tag aide: 'install'

  describe package('aide') do
    it { should be_installed }
  end
end

control 'cis-aide-1.3.2' do
  impact 1.0
  title 'Implement Periodic Execution of File Integrity'
  desc "Periodic file checking allows the system administrator to determine on a regular basis if
        critical files have been changed in an unauthorized fashion."
  tag aide: 'cron'
end
