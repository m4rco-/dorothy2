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
# = Content
# Content is the next level of abstraction beyond Message. When a stream is
# fetched from xtractr, all registered stream processors are invoked on the
# various messages. For example, the HTTP content processor, pulls out the
# response body from HTTP requests and responses, dechunks them and potentially
# unzips the content. The resulting content represents the HTML file or a JPEG
# image that can be saved off.
#
#  xtractr.packets('http.content.type:gif').first.flow.stream.contents.each do |c|
#      c.save
#  end
class Content
    # The name of the content (like a jpeg or pdf file).
    attr_accessor :name
    
    # The encoding (base64, gzip, deflate, etc) of this content.
    attr_accessor :encoding
    
    # The mime type of this content.
    attr_accessor :type
    
    # The message from which this content was extracted.
    attr_reader   :message
    
    # The actual body of the content (gunzip'd PDF file, for example)
    attr_accessor :body
    
    def initialize message # :nodoc:
        @name    = "content.#{message.stream.flow.id}.#{message.index}"
        @type    = 'application/unknown'
        @body    = nil
        @message = message
    end
    
    # Save the content to a file. If the filename is not provided then the
    # content name is used instead. This is a convenience method used for
    # method chaining.
    #  flow.stream.contents.first.save
    def save filename=nil
        open(filename || name, "w") do |ios|
            ios.write body
        end
        return self
    end
    
    def inspect # :nodoc:
        preview = body[0..32].inspect
        "#<content #{name} #{type} #{encoding} #{preview}>"
    end
end
end # Xtractr
end # Mu
