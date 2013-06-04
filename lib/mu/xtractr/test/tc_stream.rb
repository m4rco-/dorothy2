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
class Stream
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    attr_reader :stream
    
    def setup
        @xtractr = Xtractr.new
        @stream = xtractr.flows('flow.service:HTTP').first.stream
    end
    
    def test_Stream
        assert(Stream.ancestors.include?(Enumerable), "Stream doesn't mixin Enumerable")
    end
    
    def test_flow
        assert_kind_of(Flow, stream.flow)
    end
    
    def test_each
        assert_equal(stream.method(:each), stream.method(:each_message))
        assert_equal(2, stream.messages.size)
        stream.each_with_index do |m, i|
            assert_kind_of(Stream::Message, m)
            assert_equal(i, m.index)
            assert_equal(stream.__id__, m.stream.__id__)
            assert_equal(true, m.dir == 0 || m.dir == 1)
            assert_nothing_raised { m.inspect }
        end
    end
    
    def test_inspect
        assert_nothing_raised { stream.inspect }
    end
end
end # Stream
end # Xtractr
end # Mu
