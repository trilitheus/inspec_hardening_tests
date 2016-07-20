control 'cis-net-4.1.1' do
  impact 1.0
  title 'Disable IP Forwarding'
  desc "Setting the flag to 0 ensures that a server with multiple interfaces (for example, a hard
        proxy), will never be able to forward packets, and therefore, never serve as a router."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
end

control 'cis-net-4.1.2' do
  impact 1.0
  title 'Disable Send Packet Redirects'
  desc "An attacker could use a compromised host to send invalid ICMP redirects to other router
        devices in an attempt to corrupt routing and have users access a system set up by the
        attacker as opposed to a valid system."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-net-4.2.1' do
  impact 1.0
  title 'Disable Source Routed Packet Acceptance'
  desc "Setting net.ipv4.conf.all.accept_source_route and
        net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting
        source routed packets. Assume this server was capable of routing packets to Internet
        routable addresses on one interface and private addresses on another interface. Assume
        that the private addresses were not routable to the Internet routable addresses and vice
        versa. Under normal routing circumstances, an attacker from the Internet routable
        addresses could not use the server as a way to reach the private address servers. If,
        however, source routed packets were allowed, they could be used to gain access to the
        private address systems as the route could be specified, rather than rely on routing
        protocols that did not allow this routing."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should eq 0 }
  end
end

control 'cis-net-4.2.2' do
  impact 1.0
  title 'Disable ICMP Redirect Acceptance'
  desc "Attackers could use bogus ICMP redirect messages to maliciously alter the system routing
        tables and get them to send packets to incorrect networks and allow your system packets
        to be captured."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-net-4.2.3' do
  impact 1.0
  title 'Disable Secure ICMP Redirect Acceptance'
  desc "It is still possible for even known gateways to be compromised. Setting
        net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table
        updates by possibly compromised known gateways."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.secure_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.secure_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-net-4.2.4' do
  impact 1.0
  title 'Log Suspicious Packets'
  desc "Enabling this feature and logging these packets allows an administrator to investigate the
        possibility that an attacker is sending spoofed packets to their server."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should eq 1 }
  end
end

control 'cis-net-4.2.5' do
  impact 1.0
  title 'Enable Ignore Broadcast Requests Packets'
  desc "Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for
        your network could be used to trick your host into starting (or participating) in a Smurf
        attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast
        messages with a spoofed source address. All hosts receiving this message and responding
        would send echo-reply messages back to the spoofed address, which is probably not
        routable. If many hosts respond to the packets, the amount of traffic on the network could
        be significantly multiplied."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should eq 1 }
  end
end

control 'cis-net-4.2.6' do
  impact 1.0
  title 'Enable Bad Error Message Protection'
  desc "Some routers (and some attackers) will send responses that violate RFC-1122 and attempt
        to fill up a log file system with many useless error messages."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should eq 1 }
  end
end

control 'cis-net-4.2.7' do
  impact 1.0
  title 'Enable RFC-recommended Source Route Validation'
  desc "Setting these flags is a good way to deter attackers from sending your server bogus packets
        that cannot be responded to. One instance where this feature breaks down is if
        asymmetrical routing is employed. This is would occur when using dynamic routing
        protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your
        server, you will not be able to enable this feature without breaking the routing."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.rp_filter') do
    its('value') { should eq 1 }
  end
end

control 'cis-net-4.2.8' do
  impact 1.0
  title 'Enable TCP SYN Cookies'
  desc "Attackers use SYN flood attacks to perform a denial of service attacked on a server by
  sending many SYN packets without completing the three way handshake. This will quickly
  use up slots in the kernel's half-open connection queue and prevent legitimate connections
  from succeeding. SYN cookies allow the server to keep accepting valid connections, even if
  under a denial of service attack."
  tag net: 'ipv4'

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
end

# TODO: control 'cis-net-4.3' - wireless networking

control 'cis-net-4.4.2' do
  impact 1.0
  title 'Disable IPv6'
  desc "If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface
        of the system."
  tag net: 'ipv6'

  describe kernel_parameter('net.ipv6.conf.all.disable_ipv6') do
    its('value') { should eq 1 }
  end
end

# TODO: control 'cis-net-4.5' - TCP Wrapperso

control 'cis-net-4.6.1' do
  impact 1.0
  title 'Disable DCCP'
  desc "If the protocol is not required, it is recommended that the drivers not be installed
        to reduce the potential attack surface."
  tag net: 'protocols'

  describe kernel_module('dccp') do
    it { should_not be_loaded }
  end
  check_dccp = command('/sbin/modprobe -n -v dccp')
  describe check_dccp do
    its('stdout') { should match %r{install /bin/true} }
  end
end

control 'cis-net-4.6.2' do
  impact 1.0
  title 'Disable SCTP'
  desc "If the protocol is not required, it is recommended that the drivers not be installed
        to reduce the potential attack surface."
  tag net: 'protocols'

  describe kernel_module('sctp') do
    it { should_not be_loaded }
  end
  check_sctp = command('/sbin/modprobe -n -v sctp')
  describe check_sctp do
    its('stdout') { should match %r{install /bin/true} }
  end
end

control 'cis-net-4.6.3' do
  impact 1.0
  title 'Disable RDS'
  desc "If the protocol is not required, it is recommended that the drivers not be installed
        to reduce the potential attack surface."
  tag net: 'protocols'

  describe kernel_module('rds') do
    it { should_not be_loaded }
  end
  check_rds = command('/sbin/modprobe -n -v rds')
  describe check_rds do
    its('stdout') { should match %r{install /bin/true} }
  end
end

control 'cis-net-4.6.3' do
  impact 1.0
  title 'Disable TIPC'
  desc "If the protocol is not required, it is recommended that the drivers not be installed
        to reduce the potential attack surface."
  tag net: 'protocols'

  describe kernel_module('tipc') do
    it { should_not be_loaded }
  end
  check_tipc = command('/sbin/modprobe -n -v tipc')
  describe check_tipc do
    its('stdout') { should match %r{install /bin/true} }
  end
end

control 'cis-net-4.7' do
  impact 1.0
  title 'Enable firewalld'
  desc "A firewall provides extra protection for the Linux system by limiting communications in
        and out of the box to specific addresses and ports."
  tag net: 'firewall'

  describe service('firewalld') do
    it { should be_enabled }
  end
end
