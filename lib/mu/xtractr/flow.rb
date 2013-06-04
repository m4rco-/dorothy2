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
# = Flow
# Flow represents a single conversation between two hosts. Depending on whether
# it's IP, UDP or TCP, xtractr uses different information from the IP header
# of the packets (src/dst addresses and ports) to logically group them
# together. Each flow also has the duration (difference in the timestamp between
# the first and last packet in the conversation), the total bytes that were
# exchanged as well as the logical messages that were exchanged. For example:
#
# <b>Identify hosts that performed TCP port scans</b>
#
#  xtractr.flows('flow.proto:6 flow.cmsgs:0 flow.smsgs:0').count('flow.src')
#
# <b>Identify DNS queries with no response (possibly timed out)</b>
#
#  xtractr.flows('flow.service:DNS flow.smsgs:0').count('dns.qry.name')
class Flow
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    # The unique ID of the flow.
    attr_reader :id
    
    # The timestamp of the flow, determined by the first packet in the flow.
    attr_reader :time
    
    # The duration of the flow, determined by the first and last packet in the flow.
    attr_reader :duration
    
    # The source host of the flow.
    attr_reader :src
    
    # The destination host of the flow.
    attr_reader :dst
    
    # The IP protocol of the flow.
    attr_reader :proto
    
    # The source port of the flow (if applicable).
    attr_reader :sport
    
    # The destination port of the flow (if applicable).
    attr_reader :dport
    
    # The service of the flow (like DNS or HTTP).
    attr_reader :service
    
    # The title of the flow.
    attr_reader :title
    
    # The total ##packets in the flow.
    attr_reader :packets
    
    # The total ##bytes (request and response) in the flow.
    attr_reader :bytes
    
    # The logical client messages (payloads) in the flow.
    attr_reader :cmsgs
    
    # The logical server messages (payloads) in the flow.
    attr_reader :smsgs
    
    def initialize xtractr, json # :nodoc:
        @xtractr  = xtractr
        @id       = json['id']
        @time     = json['time']
        @duration = json['duration']
        @src      = Host.new xtractr, json['src']
        @dst      = Host.new xtractr, json['dst']
        @proto    = json['proto']
        @sport    = json['sport']
        @dport    = json['dport']
        @service  = Service.new xtractr, json['service']
        @title    = json['title']
        @packets  = json['packets']
        @bytes    = json['bytes']
        @cmsgs    = json['cmsgs']
        @smsgs    = json['smsgs']
        @first_id = json['first']
        @last_id  = json['last']
        @iterator = Packets.new(xtractr, :q => "pkt.flow:#{id}")
    end
    
    # Return the first packet for this flow. Together the first and last
    # packets make up the span of the flow. Read this
    # blog[http://labs.mudynamics.com/2010/09/30/visualizing-application-flows-with-xtractr/]
    # to see how these spans enable flow visualization.
    #  xtractr.flow(1).first.bytes
    def first
        @first ||= xtractr.packet @first_id
    end
    
    # Return the last packet for this flow. Together the first and last
    # packets make up the span of the flow. Read this
    # blog[http://labs.mudynamics.com/2010/09/30/visualizing-application-flows-with-xtractr/]
    # to see how these spans enable flow visualization.
    #  xtractr.flow(2).last.bytes
    def last
        @last ||= xtractr.packet @last_id
    end
    
    # Iterate over each packet in this flow.
    #  flow.each { |pkt| ... }
    def each_packet(&blk) # :yields: packet
        @iterator.each(&blk)
        return self
    end
    
    # Reassemble the TCP stream for this flow (assuming it's a TCP flow) and
    # return the stream. This is the basis for doing content extraction from
    # packets even if the packets span multiple pcaps.
    #  xtractr.service('HTTP').flows.first.stream
    def stream
        result = xtractr.json "api/flow/#{id}/stream"
        return Stream.new(xtractr, self, result)
    end
    
    # A convenience method to fetch the stream for this flow, extract the
    # content and then return an array of contents.
    #  xtractr.flows('flow.service:HTTP favicon.ico').each do |flow|
    #      flow.contents.each { |c| c.save }
    #  end
    def contents
        stream.contents
    end
    
    # Stich together a pcap made up of all packets containing this flow and
    # save it to the filename. It's possible for the packets to span multiple
    # pcaps, but xtractr makes it seamless.
    #  flow.save("foo.pcap")
    def save filename
        open(filename, "w") do |ios|
            pcap = xtractr.get "api/packets/slice", :q => "pkt.flow:#{id}"
            ios.write pcap
        end
        return self
    end
    
    def inspect # :nodoc:
        "#<flow:#{id} #{service.name} #{src.address}:#{sport} > #{dst.address}:#{dport} #{title}"
    end
    
    alias_method :each, :each_packet
end
end # Xtractr
end # Mu
