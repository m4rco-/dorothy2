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
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_about
        about = xtractr.about
        assert_equal(1778, about.packets)
        assert_equal(32, about.flows)
        assert_equal(12, about.hosts)
        assert_equal(5, about.services)
        assert_equal(171.172, about.duration)
    end
    
    def test_hosts
        hosts = xtractr.hosts
        assert_equal(12, hosts.size)
        hosts.each { |host| assert_instance_of(Host, host) }
        assert_equal(8, xtractr.hosts(/^8.18/).size)
        assert_equal(8, xtractr.hosts('8.18').size)
        assert_equal(1, xtractr.hosts(/^4.2/).size)
        assert_equal(1, xtractr.hosts('4.2').size)
    end
    
    def test_host
        [ 
            '4.2.2.1',
            '8.18.65.67',
            '8.18.65.32',
            '8.18.65.58',
            '8.18.65.82',
            '8.18.65.27',
            '8.18.65.10',
            '8.18.65.88',
            '8.18.65.89',
            '66.235.132.121',
            '192.168.1.10',
            '224.0.0.251',
        ].each do |address|
            assert_nothing_raised { xtractr.host address }
        end
        
        assert_raise(ArgumentError) { xtractr.host '1.1.1.1' }        
    end
    
    def test_services
        services = xtractr.services
        assert_equal(5, services.size)
        services.each { |service| assert_instance_of(Service, service) }
        assert_equal(2, xtractr.services(/HTTP/).size)
        assert_equal(2, xtractr.services('HTTP').size)
        assert_equal(2, xtractr.services('http').size)
    end
    
    def test_service
        [ 'DNS', 'TCP', 'HTTP', 'HTTP/XML', 'MDNS' ].each do |name|
            assert_nothing_raised { xtractr.service name }
            assert_nothing_raised { xtractr.service name.downcase }
        end
        
        assert_raise(ArgumentError) { xtractr.service 'blah' }
    end
    
    def test_fields
        fields = xtractr.fields
        assert_equal(170, fields.size)
        fields.each { |field| assert_instance_of(Field, field) }
        assert_equal(12, xtractr.fields(/^pkt\./).size)
        assert_equal(12, xtractr.fields("PKT.").size)
        assert_equal(12, xtractr.fields("pkt.").size)
    end
    
    def test_field
        [ 
            'pkt.src', 'pkt.dst', 'pkt.flow', 'pkt.id', 'pkt.pcap', 'pkt.first', 
            'pkt.dir', 'pkt.time', 'pkt.offset', 'pkt.length', 'pkt.service',
            'pkt.title'
        ].each do |name|
            assert_nothing_raised { xtractr.field name }
        end
        assert_raise(ArgumentError) { xtractr.field 'blah' }
    end
    
    def test_flows
        flows = xtractr.flows
        assert_kind_of(Flows, flows)
        assert_equal('*', flows.q)
        
        flows = xtractr.flows 'blah:foo'
        assert_equal('blah:foo', flows.q)
        
        flows = xtractr.flows 1..10
        assert_equal('flow.id:[1 10]', flows.q)
        
        flows = xtractr.flows 1...10
        assert_equal('flow.id:[1 9]', flows.q)
    end
    
    def test_flow
        flow = xtractr.flow 1
        assert_kind_of(Flow, flow)
        
        assert_raise(ArgumentError) do
            flow = xtractr.flow xtractr.about.flows+1
        end
    end
    
    def test_packets
        packets = xtractr.packets
        assert_kind_of(Packets, packets)
        assert_equal('*', packets.q)
        
        packets = xtractr.packets 'blah:foo'
        assert_equal('blah:foo', packets.q)
        
        packets = xtractr.packets 1..10
        assert_equal('pkt.id:[1 10]', packets.q)
        
        packets = xtractr.packets 1...10
        assert_equal('pkt.id:[1 9]', packets.q)
    end
    
    def test_packet
        pkt = xtractr.packet 1
        assert_kind_of(Packet, pkt)
        assert_equal(1, pkt.id)
    end
end
end # Xtractr
end # Mu
