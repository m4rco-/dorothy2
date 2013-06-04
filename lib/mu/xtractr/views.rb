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
# See http://labs.mudynamics.com/2009/04/03/interactive-couchdb/ for a quick
# tutorial on how Map/Reduce works.
class Views # :nodoc:
    # = Count
    # Count contains the results of doing a map/reduce on either flows or
    # packets. Each count contains the field on which the map/reduce was
    # performed, the unique value as all as the count of that value in the
    # flows or packets. For example to count the unique source IP address of
    # HTTP flows in the first five minutes of the index, you would do:
    #
    #  xtractr.flows('flow.service:HTTP flow.duration:[1 300]').count('flow.src')
    class Count
        attr_reader :xtractr # :nodoc:
        
        # Returns the field used for counting.
        attr_reader :field
        
        # Returns the unique value of the field.
        attr_reader :value
        
        # Returns the count of the field/value.
        attr_reader :count
        
        def initialize xtractr, field, value, count # :nodoc:
            @xtractr = xtractr
            @field   = field
            @value   = value
            @count   = count
        end
        
        # Returns a Field::Value object that can be used for further method
        # chaining.
        #  xtractr.flows.count('flow.src').first.object.count('flow.service')
        def object
            Field::Value.new xtractr, "key" => field.name, "value" => value
        end
        
        # Fetch the list of packets that contain this field value.
        #  xtractr.flows.count('flow.src').first.packets.each { |pkt ... }
        def packets q=nil
            object.packets q
        end
        
        # Iterate over each packet that contains this field value.
        #  xtractr.flows.count('flow.src').first.each_packet { |pkt ... }
        def each_packet(q=nil, &blk) # :yields: packet
            packets(q).each(&blk)
            return self
        end
        
        # Sum the numeric values of vfield, keyed by the unique values of
        # kfield. This is used for method chaining.
        #  xtractr.flows.count('flow.src').first.sum('flow.service', 'flow.bytes')
        def sum kfield, vfield
            object.sum kfield, vfield
        end
        
        def inspect # :nodoc:
            "#<count #{value} #{count}>"
        end
    end
    
    # = Sum
    # Sum contains the results of doing a map/reduce on either flows or
    # packets. Each sum contains the field on which the map/reduce was
    # performed, the unique value as all as the sum of that value in the
    # flows or packets. For example to count the bytes sent in HTTP flows
    # keyed by the source IP address, you would do:
    #
    #  xtractr.flows('flow.service:HTTP').count('flow.src', 'flow.bytes')
    class Sum
        attr_reader :xtractr # :nodoc:
        
        # Returns the field used for summing.
        attr_reader :field
        
        # Returns the unique value used as the map/reduce key.
        attr_reader :value
        
        # Returns the aggregate computed sum.
        attr_reader :sum
        
        def initialize xtractr, field, value, sum # :nodoc:
            @xtractr = xtractr
            @field   = field
            @value   = value
            @sum     = sum
        end
        
        # Returns a Field::Value object that can be used for further method
        # chaining. In the following example, we first compute the top talkers
        # (based on the bytes sent) and then use the topmost talker to count
        # the list of unique services.
        #  xtractr.flows.sum('flow.src', 'flow.bytes').first.object.count('flow.service')
        def object
            Field::Value.new xtractr, "key" => field.name, "value" => value
        end
        
        # Fetch the list of packets that contain this field value.
        #  xtractr.flows.sum('flow.src', 'flow.bytes').first.packets.each { |pkt ... }
        def packets q=nil
            object.packets q
        end
        
        # Iterate over each packet that contains this field value.
        #  xtractr.flows.sum('flow.src', 'flow.bytes').first.each_packet { |pkt ... }
        def each_packet q=nil, &blk
            packets(q).each(&blk)
            return self
        end
        
        # Count the unique values of the specified field amongst all the packets
        # that matched the query.
        #  xtractr.flows.sum('flow.src', 'flow.bytes').first.count('flow.service')
        def count _field
            object.count _field
        end
        
        def inspect # :nodoc:
            "#<sum #{value} #{sum}>"
        end
    end
    
    def self.count xtractr, field, url, opts={} # :nodoc:
        field = Field.new(xtractr, field) if field.is_a? String
        name = field.name.gsub /^(pkt|flow)\./, ''
        _opts = opts.dup
        _opts[:r] = <<-EOS
            ({
                map: function(_pf) {
                    _pf.values("#{name}", function(_value) {
                        if (_value) {
                            if (typeof(_value) === 'string') {
                                if (_value.length > 1024) {
                                    _value = _value.slice(0,1024);
                                }
                            }
                            emit(_value, 1);
                        }
                    });
                },
                reduce: function(_key, _values) {
                    return sum(_values);
                }
            })
        EOS
        result = xtractr.json url, _opts
        result['rows'].map do |row| 
            Views::Count.new(xtractr, field, row['key'], row['value'])
        end.sort { |a, b| b.count <=> a.count }
    end
    
    def self.sum xtractr, kfield, vfield, url, opts={} # :nodoc:
        kfield = Field.new(xtractr, kfield) if kfield.is_a? String
        vfield = Field.new(xtractr, vfield) if vfield.is_a? String
        kname = kfield.name.gsub /^(pkt|flow)\./, ''
        vname = vfield.name.gsub /^(pkt|flow)\./, ''
        _opts = opts.dup
        _opts[:r] = <<-EOS
            ({
                map: function(_pf) {
                    var _key = _pf["#{kname}"];
                    if (_key) {
                        if (typeof(_key) === 'string') {
                            if (_key.length > 1024) {
                                _key = _key.slice(0,1024);
                            }
                        }
                        _pf.values("#{vname}", function(_val) {
                            if (typeof(_val) === 'number') {
                                emit(_key, _val);
                            }
                        });
                    }
                },
                reduce: function(_key, _values) {
                    return sum(_values);
                }
            })
        EOS
        result = xtractr.json url, _opts
        result['rows'].map do |row| 
            Views::Sum.new(xtractr, kfield, row['key'], row['value'])
        end.sort { |a, b| b.sum <=> a.sum }
    end
end
end # Xtractr
end # Mu
