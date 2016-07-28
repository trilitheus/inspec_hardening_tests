control 'cis-ssh-7.1.1' do
  impact 1.0
  title 'Set Password Expiration Days'
  desc "The window of opportunity for an attacker to leverage compromised credentials or
        successfully compromise credentials via an online brute force attack is limited by the age of
        the password. Therefore, reducing the maximum age of a password also reduces an
        attacker's window of opportunity"
  tag config: 'login_defs'

  describe login_defs do
    its('PASS_MAX_DAYS') { should eq '90' }
  end
end

control 'cis-ssh-7.1.2' do
  impact 1.0
  title 'Set Password Change Minimum Number of Days'
  desc "By restricting the frequency of password changes, an administrator can prevent users from
        repeatedly changing their password in an attempt to circumvent password reuse controls."
  tag config: 'login_defs'

  describe login_defs do
    its('PASS_MIN_DAYS') { should eq '7' }
  end
end

control 'cis-ssh-7.1.3' do
  impact 1.0
  title 'Set Password Expirating Warning Days'
  desc "Providing an advance warning that a password will be expiring gives users time to think of
        a secure password. Users caught unaware may choose a simple password or write it down
        where it may be discovered."
  tag config: 'login_defs'

  describe login_defs do
    its('PASS_WARN_AGE') { should eq '7' }
  end
end
