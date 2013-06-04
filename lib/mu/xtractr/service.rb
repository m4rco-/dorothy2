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
# = Service
# The Service class represents the Wireshark-assigned protocol that's somewhat 
# higher level than the IP protocol. You can get a list of all the unique
# services in your index through the xtractr's methods:
#
#  xtractr.services(/http/).each { |service| ... }
#  xtractr.services.each { |service| ... }
#
# Some services like HTTP have counterparts in both flows and packets, while
# others like ARP (all non-IP, layer2 services) are only available in packets.
class Service
    attr_reader :xtractr # :nodoc:
    
    # Return the name of the service
    attr_reader :name
    
    def initialize xtractr, name # :nodoc:
        @xtractr = xtractr
        @name = name
    end
    
    # Get a unique list of clients for this service
    #  xtractr.service('http').clients
    def clients q=nil
        _q = "flow.service:\"#{name}\""
        _q << " #{q}" if q
        Flows.new(xtractr, :q => _q).count('flow.src')
    end
    
    # Get a unique list of servers for this service
    #  xtractr.service('http').servers
    def servers q=nil
        _q = "flow.service:\"#{name}\""
        _q << " #{q}" if q
        Flows.new(xtractr, :q => _q).count('flow.dst')
    end
    
    # Return an iterator that can yield all packets that have this service and
    # matches the query
    #  xtractr.service("DNS").packets("mu").each { |pkt| ... }
    def packets q=nil
        _q = "pkt.service:\"#{name}\""
        _q << " #{q}" if q
        return Packets.new(xtractr, :q => _q)
    end
    
    # Return an iterator that can yield all flows that have this service and
    # matches the query
    #  xtractr.service("DNS").flows("AAAA").each { |flow| ... }
    def flows q=nil
        _q = "flow.service:\"#{name}\""
        _q << " #{q}" if q
        return Flows.new(xtractr, :q => _q)
    end
    
    def inspect # :nodoc:
        "#<service:#{name}>"
    end
end
end # Xtractr
end # Mu
