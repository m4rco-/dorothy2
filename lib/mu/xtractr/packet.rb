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
# = Packet
# A class that represents a single packet in the xtractr index. You can
# iterate over all the packets in the index like this:
#  xtractr.packets('blah').each { |pkt| ... }
class Packet
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    # The unique ID of the packet.
    attr_reader :id
    
    # The file offset of the packet within the pcap.
    attr_reader :offset
    
    # The length of the packet (the entire frame).
    attr_reader :length
    
    # The relative timestamp of the packet.
    attr_reader :time
    
    # The direction of the packet (if it belongs to a flow).
    attr_reader :dir
    
    # The source host of the packet.
    attr_reader :src
    
    # The destination host of the packet.
    attr_reader :dst
    
    # The service of the packet.
    attr_reader :service
    
    # The title of the packet.
    attr_reader :title
    
    def initialize xtractr, json # :nodoc:
        @xtractr = xtractr
        @id      = json['id']
        @offset  = json['offset']
        @length  = json['length']
        @pcap_id = json['pcap']
        @flow_id = json['flow']
        @time    = json['time']
        @dir     = json['dir']
        @src     = Host.new xtractr, json['src']
        @dst     = Host.new xtractr, json['dst']
        @service = Service.new xtractr, json['service']
        @title   = json['title']
    end
    
    # Returns the flow (if any) that this packet belongs to.
    #  xtractr.packets('index.html').first.flow
    def flow
        return nil if @flow_id.zero?
        @flow ||= xtractr.flow @flow_id
    end
        
    # Fetch the actual packet data from the index. The return value is a
    # String (that might contain null characters).
    #  xtractr.packets('index.html').first.bytes
    def bytes
        result = xtractr.json "/api/packet/#{id}/bytes"
        result['bytes'].map { |b| b.chr }.join('')
    end
    
    # For UDP/TCP (both IPv4 and IPv6) packets, fetch just the layer4 payload. 
    # Returns an empty string for all other types of packet.
    #  xtractr.packets('http.request.method:GET').each do |pkt|
    #      puts pkt.payload
    #  end
    def payload
        result = xtractr.json "/api/packet/#{id}/bytes"
        bytes = result['bytes']
        l4size = result['l4size'] || 0
        bytes[-l4size, l4size].map { |b| b.chr }.join('')
    end
    
    # Iterate over each Field::Value in the packet. The various packet fields
    # are only available if the indexing was done with <em>--mode forensics</em>.
    #   packet.each('ip.ttl') { |fv| ... }
    def each_field(regex=nil) # :yields: value
        regex = Regexp.new(regex) if regex.is_a? String
        result = xtractr.json "/api/packet/#{id}/fields"
        rows = result['rows']
        rows = rows.select { |row| row['key'] =~ regex } if regex        
        rows.each do |row|
            value = Field::Value.new(xtractr, row)
            yield value
        end
    end
    
    # Fetch the values of the specified field for this packet. Even if there's 
    # only a single value for the field, it's returned as an array of 1 element
    #  packet.field('ip.ttl').each { |ttl| ... }
    def [] name
        result = xtractr.json "/api/packet/#{id}/field/#{name}"
        return result['rows']
    end
    
    # Extract just this packet and save it to the specified file as a pcap.
    # You can also save a collection of packets using Packets#save or a
    # collection of flows using Flows#save.
    #   packet.save("foo.pcap")
    def save filename
        open(filename, "w") do |ios|
            pcap = xtractr.get "api/packet/#{id}/pcap"
            ios.write pcap
        end
        return self
    end
    
    def inspect # :nodoc:
        "#<pkt:#{id} #{src.address} > #{dst.address} #{service.name} #{title}"
    end
    
    alias_method :each, :each_field
    alias_method :fields, :entries
    alias_method :field, :[]
end
end # Xtractr
end # Mu
