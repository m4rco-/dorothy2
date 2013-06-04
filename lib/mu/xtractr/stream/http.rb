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

require 'stringio'
require 'zlib'

module Mu
class Xtractr
class Stream
class HTTP < Processor # :nodoc:
    # Check to see if this is a HTTP stream.
    def self.matches? stream
        not stream.messages.select { |message| message.bytes =~ /HTTP\/1\./ }.empty?
    end
    
    # Pull out the response body from the messages in the stream and convert
    # them into contents on the stream.
    def self.extract stream
        stream.messages.each { |message| process stream, message }
    end
    
    def self.process stream, message
        content = Content.new message
        chunked = false
        length = nil
        ios = StringIO.new message.bytes
        while true
            line = ios.readline.chomp rescue nil
            break if not line or line.empty?
            
            case line
            when /Content-Length:\s*(\d+)/i
                length = $1.to_i
            when /Content-Type:\s*(.*)/i
                content.type = $1
            when /Content-Encoding:\s*(.*)/i
                content.encoding = $1
            when /Transfer-Encoding:\s*chunked/i
                chunked = true
            end
        end
        
        # Read the content
        bytes = ios.read(length)
        return if not bytes or bytes.empty?
                        
        # Handle chunked encoding, if necessary
        bytes = dechunk(bytes) if chunked
        
        # And then decompress, if necessary
        if ['gzip','deflate'].member? content.encoding
            bytes = decompress(bytes, content.encoding)
        end
        
        if bytes
            content.body = bytes
            stream.contents << content
        end
    end
    
    def self.dechunk text
        ios = StringIO.new text
        body = ''
        while true
            line = ios.readline rescue nil
            break if not line or line.empty?
            
            chunksz = line.to_i(16)
            break if chunksz.zero?
            
            body << ios.read(chunksz)
        end
        return body
    end
    
    def self.decompress text, method
        if method == 'gzip'
            ios = StringIO.new text
            reader = Zlib::GzipReader.new ios
            begin
                return reader.read
            ensure
                reader.close
            end
        elsif method == 'deflate'
            return Zlib::Inflate.inflate(text)
        end
    end
end
end # Stream
end # Xtractr
end # Mu
