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
# = Field
# Field represents a named packet field in the <b>xtractr</b> index. Each field 
# contains tokenized terms along with the frequency at which they occur. A
# field is a queryable object and can be used to iterate over flows or packets
# that match the Field::Value. See Flow or Packet for more information on the
# fields that are stored in the index.
#
#  xtractr.field('http.request.uri').each_packet { |packet ... }
#
# The fields are useful for quick analysis on top trending terms across the
# entire index. Here are the top HTTP fields that have NOP slides in them:
#
#  xtractr.fields(/^http/).select do |field|
#     not field.terms(/AAAAAA/i).empty?
#  end
class Field
    include Enumerable
    
    attr_reader :xtractr # :nodoc:
    
    # The name of the field.
    attr_reader :name
    
    # = Field::Value
    # Field::Value represents an instance of a field with a concrete value that 
    # can further used for fine grained searches.
    class Value
        attr_reader :xtractr # :nodoc:
        
        # Return the field object.
        attr_reader :field
        
        # Return the value of the field object.
        attr_reader :value
        
        def initialize xtractr, json # :nodoc:
            @xtractr = xtractr
            @field = Field.new(xtractr, json['key'])
            @value = json['value']
        end
        
        def q # :nodoc:
            "#{field.name}:\"#{value}\""
        end
        
        # Fetch the list of packets that contain this Field::Value. If the
        # optional query is given, it's AND'd to the query that matches this
        # Field::Value.
        #  value.packets.each { |pkt| ... }
        #  value.packets('dns.qry.name:apple').each { |pkt| ... }
        def packets _q=nil
            q2 = q
            q2 << " #{_q}" if _q
            Packets.new xtractr, :q => q2
        end
        
        # Iterate over each packet that contains this field value. This is
        # a convenience function used primiarily in method chaining.
        def each_packet(_q=nil, &blk) # :yields: packet
            packets(_q).each(&blk)
            return self
        end
        
        # Count the unique values of the specified field amongst all the packets
        # that matched the query.
        #  value.count('http.request.method')
        def count _field
            which = field.name =~ /^flow\./ ? 'flows' : 'packets'
            Views.count xtractr, _field, "/api/#{which}/report", :q => q
        end
        
        # Sum the unique numeric values of vfield, keyed by the unique values of
        # kfield.
        #   value.sum('flow.src', 'flow.bytes')
        def sum kfield, vfield
            which = field.name =~ /^flow\./ ? 'flows' : 'packets'
            Views.sum xtractr, kfield, vfield, "/api/#{which}/report", :q => q
        end
        
        def inspect # :nodoc:
            "#<value:#{field.name} #{value}>"
        end
    end
    
    def initialize xtractr, name # :nodoc:
        @xtractr = xtractr
        @name = name
    end
    
    # Fetch the terms and their packet frequencies (in packets) for this field.
    # If the optional start term is given, then the term enumeration starts
    # from the specified term.
    #  field.each { |term| ... }
    #  field.each('mozilla') { |term| ... }
    def each_term(start='') # :yields: term
        opts = {}
        opts[:start] = start
        opts[:limit] = 101
        
        while true
            result = xtractr.json "api/field/#{name}/terms", opts
            rows = result['rows']            
            break if rows.empty?
            
            rows[0, 100].each do |row| 
                term = Term.new self, row 
                yield term
            end
            
            break if rows.size < 101
            opts[:start] = rows[100]['key']
        end
        
        return self
    end
    
    # Fetch the list of <em>all</em> the unique terms for this field, sorted by the
    # frequency of occurence in the packets. This can be used for some quick
    # trend analysis to see which term of a given field appears most amongst
    # all packets in the index. Here's an example to print out the top 10 terms
    # of <em>http.request.uri</em>.
    #  p xtractr.field('http.request.uri').terms[0..10]
    def terms regex=nil
        regex = Regexp.new(regex, Regexp::IGNORECASE) if regex.is_a? String
        t = regex ? entries.select { |name| name =~ regex } : entries
        t.sort { |a, b| b.frequency <=> a.frequency }
    end
    
    # Find the term for this field which has the name and the packet frequency.
    #  field.term 'mozilla'
    def [] which
        result = xtractr.json "api/field/#{name}/terms", :start => which, :limit => 1
        rows = result['rows']
        if rows.empty? || rows[0]['key'] != which
            raise ArgumentError, "Unknown term #{which} for field #{name}"
        end
        return Term.new(self, rows[0])
    end
    
    # Find out all the unique values of this field with an optional query.
    #  xtractr.field('http.user.agent').count('flow.src:192.168.1.1')
    def count q='*'
        Views.count xtractr, self, "api/flows/report", :q => q
    end
    
    # Return a list of Field::Value objects for this field, sorted by their 
    # frequency. This is a convenience method to use the resulting Field::Value
    # objects in method chaining.
    #  xtractr.field('http.user.agent').values.first.packets.slice('foo.pcap')
    def values q='*'
        count(q).map { |c| c.object }
    end
    
    def inspect # :nodoc:
        "#<field:#{name}>"
    end
    
    alias_method :each, :each_term
    alias_method :term, :[]
end
end # Xtractr
end # Mu
