Use inspec to test server configurations

Run the commands against a remote machine that you have ssh access to:

    inspec exec test/test_spec.rb -t ssh://user:password@<hostname/IP> --sudo
