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
# = Stream
# Represents a logical TCP stream made of messages (potentially spanning
# multiple packets across multiple pcaps). A given message in the stream is
# potentially stitched together from multiple packets. Streams form the basis
# of doing content-analysis with xtractr. xtractr does all the work of
# reassembling the packets and pulling out the appropriate payload from
# each of the packets.
#
#  xtractr.flows('flow.service:http').first.stream.find do |message|
#      m =~ /xml/
#  end
#
# Each stream also has a set of content processors that are invoked at 
# creation time which pull out attachments, images, etc from the reassembled
# stream.
#
#  xtractr.flows('flow.service:http').first.stream.contents.each do |content|
#      content.save if content.type == 'image/jpeg'
#  end
class Stream
    include Enumerable
    
    # A list of stream processors that can pull out content from messages
    class Processor # :nodoc:
        def self.inherited klass
            @processors ||= [] << klass
        end
        
        def self.processors
            @processors ||= []
        end
    end
    
    attr_reader :xtractr # :nodoc:
    
    # Return the flow that this stream represents.
    attr_reader :flow
    
    # Return a list of Messages in this stream.
    attr_reader :messages
    
    # Return a list of extracted content from the messages.
    attr_reader :contents
    
    # = Message
    # Represents a single logical TCP message that has been potentially
    # reassembled from across multiple packets spanning multiple pcaps. Each
    # message contains the stream to which it belongs in addition to whether
    # this message was sent from the client or the server.
    class Message
        # Returns the stream to which this message belongs to.
        attr_reader :stream
        
        # Returns the index within the stream
        attr_reader :index
        
        # Returns the direction of the message (request/response).
        attr_reader :dir
        
        # Returns the actual bytes of the message.
        attr_reader :bytes
        
        def initialize stream, index, dir, bytes # :nodoc:
            @stream = stream
            @index  = index
            @dir    = dir
            @bytes  = bytes
        end
        
        def inspect # :nodoc:
            preview = bytes[0..32]
            preview << "..." if bytes.size > 32
            return "#<message:#{index} flow-#{stream.flow.id} #{preview.inspect}>"
        end
    end
    
    def initialize xtractr, flow, json # :nodoc:
        @xtractr  = xtractr
        @flow     = flow
        @messages = []
        @contents = []
        
        json['packets'].each do |pkt|
            bytes = (pkt['b'] || []).map { |b| b.chr }.join('')
            if messages.empty? or messages[-1].dir != pkt['d']
                messages << Message.new(self, messages.size, pkt['d'], '')
            end
            messages[-1].bytes << bytes
        end
        
        # Run the stream/messages through each registered processor to pull
        # out attachments, files, etc
        Processor.processors.each do |processor|
            if processor.matches? self
                processor.extract self
                break
            end
        end
    end
    
    # Iterate over each message in this stream
    def each_message &blk
        messages.each(&blk)
        return self
    end
    
    def inspect # :nodoc:
        return "#<stream:#{flow.id} ##{messages.size} messages>"
    end
    
    alias_method :each, :each_message
end
end # Xtractr
end # Mu

require 'mu/xtractr/stream/http'