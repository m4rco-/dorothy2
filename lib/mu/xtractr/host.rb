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
# = Host
# Host is a generic entity representing MAC, IPv4 and IPv6 addresses. You can
# get a list of all the unique hosts in the index using the root xtractr instance.
#  xtractr.hosts
class Host
    attr_reader :xtractr # :nodoc:
    
    # Returns the address of this host.
    attr_reader :address
    
    def initialize xtractr, address # :nodoc:
        @xtractr = xtractr
        @address = address
    end
    
    # Use the host as a server and get a unique list of its clients.
    #  xtractr.hosts(/192.168/).first.clients
    def clients q=nil
        _q = role2q :server, 'flow', q
        Flows.new(xtractr, :q => _q).count('flow.src')
    end
    
    # Use the host as a client and get a unique list its servers.
    #  xtractr.hosts(/192.168/).first.servers
    def servers q=nil
        _q = role2q :client, 'flow', q
        Flows.new(xtractr, :q => _q).count('flow.dst')
    end
    
    # Get a unique list of the host's services. <em>role</em> can be one of
    # :any, :client or :server to specify the role.
    #  host.services :server
    def services role =:any, q=nil
        _q = role2q role, 'flow', q
        Flows.new(xtractr, :q => _q).count('flow.service')
    end
    
    # Return a flow iterator to iterate over the various flows that contain
    # this host in the specified role.
    #  host.flows :client
    def flows role =:any, q=nil
        _q = role2q role, 'flow', q
        Flows.new(xtractr, :q => _q)
    end
    
    # Return a packet iterator to iterate over the various packets that contain
    # this host in the specified role.
    #  host.packets :server
    def packets role =:any, q=nil
        _q = role2q role, 'pkt', q
        Packets.new(xtractr, :q => _q)
    end
    
    def inspect # :nodoc:
        "#<host:#{address}>"
    end
    
    private
    def role2q role, forp, q=nil # :nodoc:
        _q = case role
                when :any:    "#{forp}.src|#{forp}.dst:\"#{address}\""
                when :client: "#{forp}.src:\"#{address}\""
                when :server: "#{forp}.dst:\"#{address}\""
                else raise ArgumentError, "Unknown role #{role}"
            end
        _q << " #{q}" if q
        return _q
    end
end
end # Xtractr
end # Mu
