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
# = About
# Contains the meta data about the index including the number of packets,
# flows, hosts, services and also the duration (in seconds) of the indexed 
# pcaps.
#
#  xtractr.about.duration
#  xtractr.about.packets
class About
    # Returns the version of the xtractr server
    attr_reader :version
    
    # Returns the ##packets in the index
    attr_reader :packets
    
    # Returns the ##flows in the index
    attr_reader :flows
    
    # Returns the ##hosts in the index
    attr_reader :hosts
    
    # Returns the ##services in the index
    attr_reader :services
    
    # Returns the total duration of all the pcaps in the index
    attr_reader :duration
    
    def initialize json # :nodoc:
        @version  = json['version']
        @packets  = json['packets']
        @flows    = json['flows']
        @hosts    = json['hosts']
        @services = json['services']
        @duration = json['duration']
    end
    
    def inspect # :nodoc:
        "#<about \##{flows} flows, \##{packets} packets>"
    end
end
end # Xtractr
end # Mu
