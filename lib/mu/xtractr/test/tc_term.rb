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
class Term
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    attr_reader :term
    
    def setup
        @xtractr = Xtractr.new
        @term = xtractr.field('http.request.method').terms.first
    end
    
    def test_Term
        assert(Term.ancestors.include?(Enumerable), "Term doesn't mixin Enumerable")
    end
    
    def test_attributes
        assert_kind_of(Field, term.field)
        assert_equal('get', term.value)
        assert_equal(116, term.frequency)
    end
    
    def test_each
        assert_equal(term.method(:each), term.method(:each_packet))
        term.each_with_index do |pkt, i|
            assert_kind_of(Packet, pkt)
            break if i < 16
        end
    end
    
    def test_packets
        packets = term.packets
        assert_equal("http.request.method:get", packets.q)
    end
    
    def test_inspect
        assert_nothing_raised { term.inspect }
    end
end
end # Term
end # Xtractr
end # Mu
