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
class Flow
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_Flow
        assert(Flow.ancestors.include?(Enumerable), "Flow doesn't mixin Enumerable")
    end
    
    def test_attributes
        flow = xtractr.flows('flow.service:HTTP').first
        assert_equal(2, flow.id)
        assert_equal(0.264773, flow.time)
        assert_equal(30.2019, flow.duration)
        assert_kind_of(Host, flow.src)
        assert_equal('192.168.1.10', flow.src.address)
        assert_kind_of(Host, flow.dst)
        assert_equal('8.18.65.67', flow.dst.address)
        assert_equal(6, flow.proto)
        assert_equal(49163, flow.sport)
        assert_equal(80, flow.dport)
        assert_kind_of(Service, flow.service)
        assert_equal('HTTP', flow.service.name)
        assert_equal('GET /WebObjects/MZStore.woa/wa/viewGrouping?id=39 HTTP/1.1 ', flow.title)
        assert_equal(28, flow.packets)
        assert_equal(19791, flow.bytes)
        assert_equal(1, flow.cmsgs)
        assert_equal(1, flow.smsgs)
        assert_equal(3, flow.instance_variable_get(:@first_id))
        assert_equal(300, flow.instance_variable_get(:@last_id))
        assert_kind_of(Packet, flow.first)
        assert_equal(3, flow.first.id)
        assert_kind_of(Packet, flow.last)
        assert_equal(300, flow.last.id)
    end
    
    def test_each
        flow = xtractr.flows('flow.service:HTTP').first
        v = flow.each { |pkt| assert_kind_of(Packet, pkt) }
        assert_equal(flow, v)
        v = flow.each_packet { |pkt| assert_kind_of(Packet, pkt) }
        assert_equal(flow, v)
    end
    
    def test_contents
        flow = xtractr.flows('flow.service:HTTP').first
        contents = flow.contents
        assert_equal(1, contents.size)
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.flows.inspect }
    end
end
end # Flow
end # Xtractr
end # Mu
