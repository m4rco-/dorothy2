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
class Service
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_clients
        service = xtractr.service('DNS')
        clients = service.clients
        assert_equal(1, clients.size)
        assert_equal('192.168.1.10', clients[0].value)
        
        service = xtractr.service('DNS')
        clients = service.clients 'flow.src:192.168.1.1'
        assert_equal(0, clients.size)
    end
    
    def test_servers
        service = xtractr.service('HTTP')
        servers = service.servers
        assert_equal(9, servers.size)
        
        servers = service.servers 'flow.dst:8.18*'
        assert_equal(8, servers.size)
    end
    
    def test_flows
        service = xtractr.service('HTTP')
        flows = service.flows
        assert_equal("flow.service:\"HTTP\"", flows.q)        
    end
        
    def test_packets
        service = xtractr.service('HTTP')
        packets = service.packets
        assert_equal("pkt.service:\"HTTP\"", packets.q)
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.services.first.inspect }
    end
end
end # Service
end # Xtractr
end # Mu
