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

require 'mu/xtractr/about'
require 'mu/xtractr/content'
require 'mu/xtractr/field'
require 'mu/xtractr/flow'
require 'mu/xtractr/flows'
require File.dirname(__FILE__) + '/xtractr/host'   #overrides the gem one with the local (fixed for 1.9.3)
require 'mu/xtractr/packet'
require 'mu/xtractr/packets'
require 'mu/xtractr/service'
require 'mu/xtractr/stream'
require 'mu/xtractr/term'
require 'mu/xtractr/views'

module Mu # :nodoc:
# = http://www.pcapr.net/static/image/favicon.png Mu::Xtractr
# :main: Mu::Xtractr
#
# This gem is Ruby front-end to the RESTful API that <b>xtractr[http://www.pcapr.net/xtractr]</b>
# provides. We primarily use this for unit testing xtractr's API, but on 
# its own this gem provides for a powerful programmable interface into 
# xtractr and is a super fast way to extract information out of large pcaps.
#
# = Getting Started
# First download <b>xtractr</b> from http://www.pcapr.net/xtractr. Follow the
# instructions to index your pcap. Finally run xtractr in browse mode and then
# you can hang out in IRB poking around flows and packets.
#
# = Examples
# You can run the xtractr-gem from within IRB which makes it a fun interactive 
# network forensics tool. Make sure you are running the xtractr binary in 
# browse mode. Turning on auto-completion in IRB also makes it easier to try out
# different things and interactively experiment with the API:
#
#  $ irb -rirb/completion -rmu/xtractr
#
# All of the examples below work off the test/test.pcap bundled with the gem.
# We'll also assume that you've done this at the start of the IRB session:
#
#  irb> xtractr = Mu::Xtractr.new
#
# <b>Top DNS query names</b>
#
# We first pull out all DNS flows and then map/reduce the unique values of
# the <em>dns.qry.name</em>.
#  irb> xtractr.flows('flow.service:DNS').values('dns.qry.name')
#
# <b>Services used by the top talker (based on bytes sent/received)</b>
#
# We first sum the total number of bytes using the src address as the key. The
# sum function returns the matches sorted by the #bytes. We then use the first
# object (the top talker) to in turn map/reduce the unique list of services
# supported by it.
#  irb> xtractr.flows.sum('flow.src', 'flow.bytes').first.count('flow.service')
#
# <b>Generating #new pcaps based on search criteria</b>
# 
# We first get a list of the unique HTTP methods in the index and then for each of
# methods, query for all the packets and then save them into a new pcap.
#  irb> xtractr.packets.count('http.request.method').each { |c| c.packets.save("#{c.value}.pcap") }
#
#--
# rdoc --exclude test --force-update --inline-source --op mu/xtractr/doc --main Mu::Xtractr
class Xtractr
    # Return the IP address of the xtractr instance
    attr_reader :address
    
    # Return the listening port of the xtractr instance
    attr_reader :port
    
    # Relative URL
    attr_reader :relurl
    
    # Create a new instance to connect to the xtractr binary using a
    # url.
    #   Xtractr.create 'http://some.host:8080/'
    def self.create url
        uri = URI.parse url
        self.new uri.host, uri.port, uri.path
    end
    
    # Create a new instance to connect to the xtractr binary running in
    # browse mode.
    #   Xtractr.new
    #   Xtractr.new 'localhost', 8080
    def initialize address='localhost', port=8080, relurl=nil
        @address = address
        @port = port
        @relurl = relurl || '/'
        @relurl << '/' if @relurl[-1,1] != '/'            
        #unless about.version =~ /^4\.5\.(svn|41604)$/
        #    puts "boh"
        #    puts "xtractr version #{about.version} out of date!"
        #    puts "please download a new one from http://www.pcapr.net/xtractr"
        #    raise
        #end
    end
    
    # Fetch the meta data about the index. This includes information about
    # the total number of packets, flows as well as the duration of the entire
    # set of pcaps in the index.
    #  xtractr.about
    def about
        @about ||= About.new json('api/about')
    end
    
    # Fetch the list of fields in the index. The fields are only available
    # if the <em>--mode forensics</em> was used during the indexing process.
    #  xtractr.fields
    #  xtractr.fields /^http/
    #  xtractr.fields 'http.server'
    def fields regex=nil
        regex = Regexp.new(regex, Regexp::IGNORECASE) if regex.is_a? String
        result = (@fields ||= json 'api/fields')
        result = result.select { |name| name =~ regex } if regex
        return result.map { |name| Field.new self, name }
    end
    
    # Fetch a field of the given name.
    #  xtractr.field 'http.server'
    def field name
        obj = fields.find { |f| f.name == name }
        raise ArgumentError, "Unknown field #{name}" if not obj
        return obj
    end
    
    # Fetch the list of hosts in the index. The optional regex (or String)
    # can be used to filter the hosts list.
    #  xtractr.hosts
    #  xtractr.hosts /192.168/
    #  xtractr.hosts '10.10'
    def hosts regex=nil
        regex = Regexp.new(regex, Regexp::IGNORECASE) if regex.is_a? String
        result = (@hosts ||= json 'api/hosts')
        rows = result['rows']
        rows = rows.select { |row| row['name'] =~ regex } if regex
        return rows.map { |row| Host.new self, row['name'] }
    end
    
    # Fetch a host of the given address.
    #  xtractr.host '192.168.1.1'
    def host address
        obj = hosts.find { |h| h.address == address }
        raise ArgumentError, "Unknown host #{address}" if not obj
        return obj
    end
    
    # Fetch the list of services in the index. The optional regex (or String)
    # can be used to filter the services lists.
    #  xtractr.services
    #  xtractr.services /http/
    #  xtractr.services 'sip'
    def services regex=nil
        regex = Regexp.new(regex, Regexp::IGNORECASE) if regex.is_a? String
        result = (@services ||= json 'api/services')
        rows = result['rows']
        rows = rows.select { |row| row['name'] =~ regex } if regex
        return rows.map { |row| Service.new self, row['name'] }
    end
    
    # Fetch a service of the given name.
    #  xtractr.service 'dns'
    def service name
        obj = services.find { |s| s.name.downcase == name.downcase }
        raise ArgumentError, "Unknown service #{name}" if not obj
        return obj
    end
    
    # Return an iterator that can yield each flow that matched the query. If
    # <em>q</em> is a Range, then it's used to extract the set of flows that match
    # all of those ids.
    #  xtractr.flows.each { |flow| ... }
    #  xtractr.flows(1..10).each { |flow| ... }
    #  xtractr.flows("flow.src:192.168.1.1").each { |flow| ... }
    def flows(q='*') # :yields: flow
        if q.is_a? Range
            first = q.first
            last  = q.last
            last -= 1 if q.exclude_end?
            q = "flow.id:[#{first} #{last}]"
        end
        return Flows.new(self, :q => q)
    end
    
    # Return the id'th flow from the index.
    #  xtractr.flow 1
    def flow id
        result = json "api/flows", :start => id, :limit => id
        rows = result['rows']
        raise ArgumentError, "Unknown flow #{id}" if rows.empty?
        return Flow.new(self, rows[0])
    end
    
    # Return an iterator that can yield each packet that matched the query. If
    # <em>q</em> is a Range, then it's used to extract the set of packets that match
    # all of those ids.
    #  xtractr.packets.each { |pkt| ... }
    #  xtractr.packets(5..32).each { |pkt| ... }
    #  xtractr.packets("http.user.agent:mozilla").each { |pkt| ... }
    def packets(q='*') # :yields: packet
        if q.is_a? Range
            first = q.first
            last  = q.last
            last -= 1 if q.exclude_end?
            q = "pkt.id:[#{first} #{last}]"
        end
        return Packets.new(self, :q => q)
    end
    
    # Return the id'th packet from the index.
    #  xtractr.packet 1
    def packet id
        result = json "api/packets", :start => id, :limit => id
        rows = result['rows']
        raise ArgumentError, "Unknown packet #{id}" if rows.empty?
        return Packet.new(self, rows[0])
    end
    
    # Fetch the URL with the GET parameters and interpret the response body
    # as a JSON object
    def json url, opts={} # :nodoc:
        res = get url, opts
        js = JSON.parse(res)
        raise ArgumentError, js['reason'] if js.is_a?(Hash) and js['error']
        return js
    end
    
    # Fetch the URL and return the response body, as is
    def get url, opts={} # :nodoc:
        _url = relurl + url
        if opts.size
            _url << '?'
            _url << opts.keys.map { |key| key.to_s + '=' + opts[key].to_s }.join('&')
        end
        
        _url = "http://#{address}:#{port}" + URI.escape(_url)
        return Net::HTTP.get(URI.parse(_url))
    end
    
    def inspect # :nodoc:
        "#<xtractr #{address}:#{port}>"
    end
end
end # Mu
