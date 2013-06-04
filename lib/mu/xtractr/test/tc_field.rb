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
class Field
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_Field
        assert(Field.ancestors.include?(Enumerable), "Field doesn't mixin Enumerable")
    end
    
    def test_each
        field = xtractr.field('pkt.src')
        terms = field.terms
        assert_equal(11, terms.size)
        terms.each { |t| assert_kind_of(Term, t) }
        
        val = field.each_term { |t| assert_kind_of(Term, t) }
        assert_equal(field, val)
    end
    
    def test_terms
        field = xtractr.field('dns.qry.name')
        terms = field.terms
        assert_equal(12, terms.size)
        assert_equal(true, terms.first.frequency > terms.last.frequency)
        
        field.terms(/itunes/).each do |term|
            assert_match(/itunes/, term.value)
        end
    end
        
    def test_term
        field = xtractr.field('dns.qry.name')
        
        [ :[], :term ].each do |method|
            term = field.send method, 'itunes'
            assert_kind_of(Term, term)
            assert_equal('itunes', term.value)
            assert_equal(3, term.frequency)
        end
        
        assert_raise(ArgumentError) { field['foo'] }
    end
    
    def test_count
        field = xtractr.field('dns.qry.name')
        counts = field.count
        assert_equal(7, counts.size)
        counts.each { |v| assert_kind_of(Views::Count, v) }
        
        counts = field.count('flow.dst:4.2.2.1')
        assert_equal(4, counts.size)
        counts.each { |v| assert_kind_of(Views::Count, v) }
    end
    
    def test_values
        field = xtractr.field('dns.qry.name')
        values = field.values
        assert_equal(7, values.size)
        values.each { |v| assert_kind_of(Field::Value, v) }
        
        values = field.values('flow.dst:4.2.2.1')
        assert_equal(4, values.size)
        values.each { |v| assert_kind_of(Field::Value, v) }
    end
    
    def test_inspect
        field = xtractr.field('dns.qry.name')
        assert_nothing_raised { field.inspect }
    end
    
    class Value
    class Test < ::Test::Unit::TestCase
        attr_reader :xtractr
        attr_reader :value
        
        def setup
            @xtractr = Xtractr.new
            @value = xtractr.field('dns.qry.name').values.first
        end
        
        def test_q
            assert_equal('dns.qry.name:"ax.search.itunes.apple.com"', value.q)
        end
        
        def test_packets
            packets = value.packets
            assert_kind_of(Packets, packets)
            assert_equal('dns.qry.name:"ax.search.itunes.apple.com"', packets.q)
        end
        
        def test_each_packet
            v = value.each_packet { |pkt| assert_kind_of(Packet, pkt) }
            assert_equal(value, v)
        end
        
        def test_count
            value.count('pkt.src').each do |c|
                assert_kind_of(Views::Count, c)
                assert_equal('pkt.src', c.field.name)
            end
        end
        
        def test_sum
            value.sum('pkt.src', 'pkt.length').each do |s|
                assert_kind_of(Views::Sum, s)
                assert_equal('pkt.src', s.field.name)
            end
        end
        
        def test_inspect
            assert_nothing_raised { value.inspect }
        end
    end
    end
end
end # Field
end # Xtractr
end # Mu
