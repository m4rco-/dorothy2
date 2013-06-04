# "THE BEER-WARE LICENSE" (Revision 42):
# Mu[http://www.mudynamics.com] wrote this file. As long as you retain this 
# notice you can do whatever you want with this stuff. If we meet some day, 
# and you think this stuff is worth it, you can buy us a beer in return. 
#
# All about pcapr
# * http://www.pcapr.net
# * http://groups.google.com/group/pcapr-forum
# * http://twitter.com/pcapr
#
# Mu Dynamics
# * http://www.mudynamics.com
# * http://labs.mudynamics.com

require 'mu/xtractr'
require 'test/unit'

module Mu
class Xtractr
class Host
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_clients
        host = xtractr.host('192.168.1.10')
        assert_equal(true, host.clients.empty?)
        
        host = xtractr.host('8.18.65.32')
        assert_equal(1, host.clients.size)
        assert_equal('192.168.1.10', host.clients[0].value)
    end
    
    def test_servers
        host = xtractr.host('8.18.65.32')
        assert_equal(true, host.servers.empty?)
        
        host = xtractr.host('192.168.1.10')
        assert_equal(11, host.servers.size)
        assert_equal('4.2.2.1', host.servers[0].value)
    end
    
    def test_services
        host = xtractr.host('192.168.1.10')
        services = host.services
        assert_equal(3, services.size)
        assert_equal('HTTP', services[0].value)
        assert_equal('DNS', services[1].value)
        assert_equal('MDNS', services[2].value)
        
        services = host.services :client
        assert_equal(3, services.size)
        assert_equal('HTTP', services[0].value)
        assert_equal('DNS', services[1].value)
        assert_equal('MDNS', services[2].value)
        
        services = host.services :server
        assert_equal(true, services.empty?)
        
        host = xtractr.host('4.2.2.1')
        services = host.services
        assert_equal(1, services.size)
        assert_equal('DNS', services[0].value)
        
        services = host.services :client
        assert_equal(true, services.empty?)
        
        services = host.services :server        
        assert_equal(1, services.size)
        assert_equal('DNS', services[0].value)
    end
    
    def test_flows
        host = xtractr.host('192.168.1.10')
        flows = host.flows
        assert_equal("flow.src|flow.dst:\"192.168.1.10\"", flows.q)
        
        flows = host.flows :any
        assert_equal("flow.src|flow.dst:\"192.168.1.10\"", flows.q)
        
        flows = host.flows :client
        assert_equal("flow.src:\"192.168.1.10\"", flows.q)
        
        flows = host.flows :server
        assert_equal("flow.dst:\"192.168.1.10\"", flows.q)
        
        assert_raise(ArgumentError) { host.flows :blah }
    end
        
    def test_packets
        host = xtractr.host('192.168.1.10')
        packets = host.packets
        assert_equal("pkt.src|pkt.dst:\"192.168.1.10\"", packets.q)
        
        packets = host.packets :any
        assert_equal("pkt.src|pkt.dst:\"192.168.1.10\"", packets.q)
        
        packets = host.packets :client
        assert_equal("pkt.src:\"192.168.1.10\"", packets.q)
        
        packets = host.packets :server
        assert_equal("pkt.dst:\"192.168.1.10\"", packets.q)
        
        assert_raise(ArgumentError) { host.packets :blah }
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.hosts.first.inspect }
    end
end
end # Host
end # Xtractr
end # Mu
