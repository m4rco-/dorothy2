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
# Flows is an iterator for the flows in the index, based on a given query.
# The default query for this iterator is '*', implying that it will iterate
# over <em>all</em> the flows in the index.
class Flows
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    MAX_PAGE_SIZE = 100 # :nodoc:
    
    def initialize xtractr, opts # :nodoc:
        @xtractr = xtractr
        @opts = opts.dup
        @opts[:q] ||= '*'
    end
    
    def q # :nodoc:
        @opts[:q]
    end
    
    # Iterate over each flow that matches the search criteria. It's always
    # better to use this with a fine-grained query instead of flows.to_a
    # because it's going to try and load *all* flows from the index.
    #  xtractr.flows("flow.src:192.168.1.1").each { |flow| ... }
    def each_flow() # :yields: flow
        _opts = @opts.dup
        _opts[:start] ||= 1
        _opts[:limit] ||= MAX_PAGE_SIZE
        
        while true
            result = xtractr.json "api/flows", _opts
            rows = result['rows']            
            break if rows.empty?
                        
            rows[0, MAX_PAGE_SIZE-1].each do |row| 
                flow = Flow.new xtractr, row 
                yield flow
            end
            
            break if rows.size < MAX_PAGE_SIZE
            _opts[:start] = rows[MAX_PAGE_SIZE-1]['id']
        end
        return self
    end
    
    # Fetch the first flow that matched the query. This is mainly used for
    # unit testing, but useful within IRB to experiment with method chaining.
    #  flows.first.save("1.pcap")
    def first
        result = xtractr.json "api/flows", :start => 1, :limit => 1, :q => q
        rows = result['rows']
        rows.empty? ? nil : Flow.new(xtractr, rows[0])
    end
    
    # Count the unique values of the specified field amongst all the flows
    # that matched the query.
    #  xtractr.flows('index.html').count('http.request.uri')
    def count field
        Views.count xtractr, field, '/api/flows/report', @opts
    end
    
    # Return a list of Field::Value objects for the specified field, sorted
    # by their frequency. This is a convenience method used in method chaining.
    #  xtractr.flows('index.html').values('http.request.uri')
    def values field
        count(field).map { |c| c.object }
    end
    
    # Sum the numeric values of vfield, keyed by the unique values of
    # kfield.
    #  xtractr.flows('index.html').sum('http.request.uri', 'flow.bytes')
    def sum kfield, vfield
        Views.sum xtractr, kfield, vfield, '/api/flows/report', @opts
    end
    
    # Save all the packets for this collection of flows into a pcap. It's
    # possible that the packets for the flows might span multiple indexed
    # pcaps.
    #  xtractr.flows('flow.service:DNS AAAA').save('dns.pcap')
    def save filename
        flow_ids = []
        each_flow do |flow| 
            flow_ids << flow.id.to_s
            break if flow_ids.size >= 1024
        end
        
        _q = "pkt.flow:(" << flow_ids.join('||') << ')'
        open(filename, "w") do |ios|
            pcap = xtractr.get "api/packets/slice", :q => _q
            ios.write pcap
        end
        return self
    end
    
    def inspect # :nodoc:
        "#<flows:#{@opts[:q]}>"
    end
        
    alias_method :each, :each_flow
end
end # Xtractr
end # Mu
