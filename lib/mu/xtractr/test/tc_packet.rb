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
class Packet
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_Packet
        assert(Packet.ancestors.include?(Enumerable), "Packet doesn't mixin Enumerable")
    end
    
    def test_attributes
        pkt = xtractr.packets('pkt.service:HTTP').first
        assert_equal(6, pkt.id)
        assert_equal(606, pkt.offset)
        assert_equal(412, pkt.length)
        assert_equal(0.313968, pkt.time)
        assert_equal(0, pkt.dir)
        assert_kind_of(Host, pkt.src)
        assert_equal('192.168.1.10', pkt.src.address)
        assert_kind_of(Host, pkt.dst)
        assert_equal('8.18.65.67', pkt.dst.address)
        assert_kind_of(Service, pkt.service)
        assert_equal('HTTP', pkt.service.name)
        assert_equal('GET /WebObjects/MZStore.woa/wa/viewGrouping?id=39 HTTP/1.1 ', pkt.title)
        
        assert_equal(2, pkt.instance_variable_get(:@flow_id))
        assert_nil(pkt.instance_variable_get(:@flow))
        flow = pkt.flow
        assert_kind_of(Flow, flow)
        assert_equal(2, flow.id)
        assert_not_nil(pkt.instance_variable_get(:@flow))
        flow2 = pkt.flow
        assert_equal(flow.__id__, flow2.__id__)
    end
    
    def test_bytes
        pkt = xtractr.packets('pkt.service:HTTP').first
        bytes = pkt.bytes
        assert_equal(412, bytes.size)
        assert_match(/WebObjects/, bytes)
    end
    
    def test_payload
        pkt = xtractr.packets('pkt.service:HTTP').first
        payload = pkt.payload
        assert_equal(346, payload.size)
        assert_match(/^GET/, payload)
    end
    
    def test_each
        pkt = xtractr.packets('pkt.service:HTTP').first
        pkt.each { |fv| assert_kind_of(Field::Value, fv) }
        pkt.each(/ip.ttl/) do |fv| 
            assert_kind_of(Field::Value, fv)
            assert_match(/ip\.ttl/, fv.field.name)
        end
        pkt.each_field { |fv| assert_kind_of(Field::Value, fv) }
    end
    
    def test_field
        pkt = xtractr.packets('pkt.service:HTTP').first
        values = pkt['http.request.method']
        assert_kind_of(Array, values)
        assert_equal(1, values.size)
        assert_equal("GET", values[0])
        
        values = pkt.field 'http.request.method'
        assert_kind_of(Array, values)
        assert_equal(1, values.size)
        assert_equal("GET", values[0])
    end
    
    def test_save
        filename = '/tmp/foo.pcap'
        pkt = xtractr.packets('pkt.service:HTTP').first
        pkt.save filename
        assert_equal(true, File.exist?(filename))
        assert_equal(452, File.size(filename))
    ensure
        File.unlink filename
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.packets('pkt.service:DNS').first.inspect }
    end
end
end # Packet
end # Xtractr
end # Mu
