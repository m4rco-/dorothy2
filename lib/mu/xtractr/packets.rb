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
# = Packets
# Packets is an iterator on a collection of packets determined by the search
# query. This class can also be used to report on the collection of packets
# in addition to slicing those packets into a new pcap.
#
#  xtractr.packets('http.request.method:GET pkt.src:192.168.1.1').save('foo.pcap')
#
# <b>Find the top URL's in HTTP packets</b>
#
#  xtractr.packets('pkt.service:HTTP').count('http.request.method')
#
# <b>Find the packet size distribution for DNS packets</b>
#
#  xtractr.packets('pkt.service:DNS').count('pkt.length')
class Packets
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    MAX_PAGE_SIZE = 100 # :nodoc:
    
    def initialize xtractr, opts # :nodoc:
        @xtractr = xtractr
        @opts = opts
        @opts[:q] ||= '*'
    end
    
    def q # :nodoc:
        @opts[:q]
    end
    
    # Iterate over each packet that matches the search criteria. It's always
    # better to use this with a fine-grained query instead of packets.to_a
    # because it's going to try and load <em>all</em> packets from the index.
    #  xtractr.packets("pkt.src:192.168.1.1").each do |pkt|
    #      ...
    #  end
    def each_packet() # :yields: packet
        _opts = @opts.dup
        _opts[:start] ||= 1
        _opts[:limit] ||= MAX_PAGE_SIZE
        
        while true
            result = xtractr.json "api/packets", _opts
            rows = result['rows']            
            break if rows.empty?
                        
            rows[0, MAX_PAGE_SIZE-1].each do |row| 
                packet = Packet.new xtractr, row 
                yield packet
            end
            
            break if rows.size < MAX_PAGE_SIZE
            _opts[:start] = rows[MAX_PAGE_SIZE-1]['id']
        end        
        return self
    end
    
    # Fetch the first packet that matched the query. Mostly used for unit
    # testing.
    def first
        result = xtractr.json "api/packets", :start => 1, :limit => 1, :q => q
        rows = result['rows']
        rows.empty? ? nil : Packet.new(xtractr, rows[0])
    end
    
    # Count the unique values of the specified field amongst all the packets
    # that matched the query.
    #  xtractr.packets('mozilla').count('http.request.uri')
    def count field
        Views.count xtractr, field, '/api/packets/report', @opts
    end
    
    # Return a list of Field::Value objects for the specified field, sorted
    # by their frequency. This is a convenience method used in method chaining.
    #  xtractr.packets('index.html').values('http.request.uri')
    def values field
        count(field).map { |c| c.object }
    end
    
    # Sum the numeric values of vfield, keyed by the unique values of
    # kfield.
    #  xtractr.packets('mozilla').sum('http.request.uri', 'pkt.length')
    def sum kfield, vfield
        Views.sum xtractr, kfield, vfield, '/api/packets/report', @opts
    end
    
    # Stich together a pcap made up of all packets that matched the query
    # and save it to the filename.
    #  xtractr.packets('pkt.service:DNS pkt.length:>64').save('foo.pcap')
    def save filename
        open(filename, "w") do |ios|
            pcap = xtractr.get "api/packets/slice", :q => @opts[:q]
            ios.write pcap
        end
        return self
    end
    
    def inspect # :nodoc:
        "#<packets:#{@opts[:q]}>"
    end
        
    alias_method :each, :each_packet
end
end # Xtractr
end # Mu
