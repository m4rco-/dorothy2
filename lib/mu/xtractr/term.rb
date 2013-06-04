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

module Mu
class Xtractr
# = Term
# A term represents a tokenized value of a field that also contains the
# frequency of occurence across all of the packets in a given index. Terms
# are useful to get quick snapshots of the index as well as in trend analysis.
# For example the following shows the top HTTP request methods as well as the
# frequency of those methods across all of the packets.
#
#  xtractr.field('http.request.method').terms.each do |term|
#    p [ term.value, term.frequency ]
#  end
class Term
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    # Return the field containing this term.
    attr_reader :field
    
    # Return the value of this term.
    attr_reader :value
    
    # Return the (packet) frequency of this term.
    attr_reader :frequency
    
    def initialize field, json # :nodoc:
        @field     = field
        @xtractr   = field.xtractr
        @value     = json['key']
        @frequency = json['value']
    end
    
    # Fetch each packet from the index that has this term in this field. If
    # the optional q is specified, the search query is AND'd with the term's
    # own search query
    #  field.term('mozilla').each { |pkt| ... }
    def each_packet(q=nil, &blk) # :yields: packet
        _q = "#{field.name}:#{value}"
        _q << " #{q}" if q
        return Packets.new(xtractr, :q => _q).each(&blk)
    end
    
    # Return an instance of Packets that serves as an iterator for all packets
    # containing this term.
    def packets q=nil
        _q = "#{field.name}:#{value}"
        _q << " #{q}" if q
        return Packets.new(xtractr, :q => _q)
    end
    
    def inspect # :nodoc:
        "#<term:#{field.name} #{value} #{frequency}>"
    end

    alias_method :each, :each_packet
end
end # Xtractr
end # Mu
