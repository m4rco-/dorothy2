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
class HTTP
class Test < Test::Unit::TestCase
    attr_reader :xtractr
    attr_reader :flow
    
    def setup
        @xtractr = Xtractr.new
    end
    
    def test_extract
        stream = xtractr.packets('http.content.type:gif').first.flow.stream
        assert_equal(1, stream.contents.size)
        content = stream.contents.first
        assert_nothing_raised { content.inspect }
        assert_equal('image/gif', content.type)
        assert_nil(content.encoding)
        assert_equal('content.4.1', content.name)
        assert_equal(content.message.__id__, stream.messages[1].__id__)
        
        stream = xtractr.packets('http.content.type:xml').first.flow.stream
        assert_equal(1, stream.contents.size)
        content = stream.contents.first
        assert_nothing_raised { content.inspect }
        assert_equal('text/xml', content.type)
        assert_equal('gzip', content.encoding)
        assert_equal('content.2.1', content.name)
        assert_equal(content.message.__id__, stream.messages[1].__id__)
    end    
end
end # HTTP
end # Stream
end # Xtractr
end # Mu
