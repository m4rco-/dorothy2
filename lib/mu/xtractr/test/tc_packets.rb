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
class Packets
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_Packets
        assert(Packets.ancestors.include?(Enumerable), "Packets doesn't mixin Enumerable")
    end
    
    def test_each
        pkts = xtractr.packets(1..10)
        pkts.each { |pkt| assert_kind_of(Packet, pkt) }
        pkts.each_packet { |pkt| assert_kind_of(Packet, pkt) }
        pkts.each_with_index { |pkt, i| assert_equal(i+1, pkt.id) }
    end
    
    def test_first
        pkt = xtractr.packets(1..10).first
        assert_kind_of(Packet, pkt)
        assert_equal(1, pkt.id)
    end
    
    def test_count
        counts = xtractr.packets(1..10).count('pkt.src')
        assert_equal(3, counts.size)
        counts.each { |c| assert_kind_of(Views::Count, c) }
        assert_equal(true, counts[0].count > counts[-1].count)
    end
    
    def test_values
        values = xtractr.packets(1..10).values('pkt.src')
        assert_equal(3, values.size)
        values.each do |v| 
            assert_kind_of(Field::Value, v)
            assert_equal('pkt.src', v.field.name)
        end
    end
    
    def test_sum
        sums = xtractr.packets(1..10).sum('pkt.src', 'pkt.length')
        assert_equal(3, sums.size)
        sums.each { |s| assert_kind_of(Views::Sum, s) }
        assert_equal(true, sums[0].sum > sums[-1].sum)
    end
    
    def test_save
        filename = '/tmp/foo.pcap'
        pkts = xtractr.packets('pkt.service:HTTP pkt.dir:0')
        pkts.save filename
        assert_equal(true, File.exist?(filename))
        assert_equal(53015, File.size(filename))
    ensure
        File.unlink filename
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.packets(1..10).inspect }
    end
end
end # Packets
end # Xtractr
end # Mu
