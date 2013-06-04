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
class Flows
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_Flows
        assert(Flows.ancestors.include?(Enumerable), "Flows doesn't mixin Enumerable")
    end
    
    def test_q
        flows = xtractr.flows
        assert_equal('*', flows.q)
        
        flows = xtractr.flows 'flow.service:DNS'
        assert_equal('flow.service:DNS', flows.q)        
    end
    
    def test_each
        flows = xtractr.flows 'flow.service:DNS'
        v = flows.each { |f| assert_kind_of(Flow, f) }
        assert_equal(flows, v)
        
        v = flows.each_flow { |f| assert_kind_of(Flow, f) }
        assert_equal(flows, v)
    end
    
    def test_first
        flows = xtractr.flows 'flow.service:DNS'
        flow = flows.first
        assert_kind_of(Flow, flow)
        
        flow = xtractr.flows('flow.service:blah').first
        assert_nil(flow)
    end
    
    def test_count
        flows = xtractr.flows 'flow.service:DNS'
        counts = flows.count 'dns.qry.name'
        assert_equal(4, counts.size)
        counts.each { |c| assert_kind_of(Views::Count, c) }
    end
    
    def test_values
        flows = xtractr.flows 'flow.service:DNS'
        values = flows.values 'dns.qry.name'
        assert_equal(4, values.size)
        values.each { |v| assert_kind_of(Field::Value, v) }
    end
    
    def test_sum
        flows = xtractr.flows 'flow.service:DNS'
        sums = flows.sum 'dns.qry.name', 'flow.bytes'
        assert_equal(4, sums.size)
        sums.each { |s| assert_kind_of(Views::Sum, s) }
    end
    
    def test_save
        filename = '/tmp/foo.pcap'
        xtractr.flows(1..3).save(filename)
        assert_equal(true, File.exist?(filename))
        assert_equal(20898, File.size(filename))
    ensure
        File.unlink filename
    end
    
    def test_inspect
        assert_nothing_raised { xtractr.flows.inspect }
    end
end
end # Flows
end # Xtractr
end # Mu
