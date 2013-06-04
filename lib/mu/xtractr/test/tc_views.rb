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
class Views
    class Count
    class Test < Test::Unit::TestCase
        attr_reader :xtractr
        attr_reader :count
    
        def setup
            @xtractr = Xtractr.new
            @count = xtractr.flows('flow.service:DNS').count('dns.qry.name').first
        end
    
        def test_attributes
            assert_kind_of(Field, count.field)
            assert_equal('ax.search.itunes.apple.com', count.value)
            assert_equal(8, count.count)
        end
        
        def test_object
            object = count.object
            assert_kind_of(Field::Value, object)
            assert_equal('dns.qry.name', object.field.name)
            assert_equal('ax.search.itunes.apple.com', object.value)
        end
    
        def test_packets
            packets = count.packets
            assert_equal("dns.qry.name:\"ax.search.itunes.apple.com\"", packets.q)
        end
    
        def test_each_packet
            count.each_packet do |pkt| 
                assert_kind_of(Packet, pkt)
                values = pkt['dns.qry.name']
                assert_equal(1, values.size)
                assert_equal('ax.search.itunes.apple.com', values[0])
            end
        end
        
        def test_sum
            sums = count.object.sum('pkt.src', 'pkt.length')
            assert_equal(2, sums.length)
        end
    
        def test_inspect
            assert_nothing_raised { count.inspect }
        end
    end
    end # Count
    
    class Sum
    class Test < Test::Unit::TestCase
        attr_reader :xtractr
        attr_reader :sum
    
        def setup
            @xtractr = Xtractr.new
            @sum = xtractr.flows('flow.service:DNS').sum('dns.qry.name', 'flow.bytes').first
        end
    
        def test_attributes
            assert_kind_of(Field, sum.field)
            assert_equal('ax.search.itunes.apple.com', sum.value)
            assert_equal(1220, sum.sum)
        end
        
        def test_object
            object = sum.object
            assert_kind_of(Field::Value, object)
            assert_equal('dns.qry.name', object.field.name)
            assert_equal('ax.search.itunes.apple.com', object.value)
        end
    
        def test_packets
            packets = sum.packets
            assert_equal("dns.qry.name:\"ax.search.itunes.apple.com\"", packets.q)
        end
    
        def test_each_packet
            sum.each_packet do |pkt| 
                assert_kind_of(Packet, pkt)
                values = pkt['dns.qry.name']
                assert_equal(1, values.size)
                assert_equal('ax.search.itunes.apple.com', values[0])
            end
        end
        
        def test_count
            counts = sum.object.count('pkt.service')
            assert_equal(1, counts.length)
        end
    
        def test_inspect
            assert_nothing_raised { sum.inspect }
        end
    end
    end # Sum
end # Views
end # Xtractr
end # Mu
