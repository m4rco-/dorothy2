#Class with some snippets

module Dorothy

class Util
	
	def write(file, string)
		File.open(file , 'w') {|f| f.write(string) }
	end
	
end

class Insertdb
	
	def initialize
		@conn = PGconn.open(:host=> DoroEnv::DBHOST, :dbname=>DoroEnv::DBNAME, :user=>DoroEnv::DBUSER, :password=>DoroEnv::DBPASS)
		return @conn		
	end		
	
	def begin_t
		@conn.exec("BEGIN")
	end
	
	def commit 
		@conn.exec("COMMIT")
	end
	
	def rollback
		LOGGER.error "DB", "DB ROLLBACK"
		@conn.exec("ROLLBACK") 
	end
	
	def insert(table,values)
		n = 1
		@sqlstring = ""
		
		values.each { |value| 
			if value == "default"
				value1 = value
				elsif value == "null"	
				value1 = value
				elsif value == "lastval()"
				value1 = value
				elsif value =~ /currval/
				value1 = value
				else
				value1 = "'#{value}'" 
			end	
			if n == values.size
				@sqlstring << value1 
				elsif 
				@sqlstring << value1 + ","
			end
			n += 1
		}				
		#p "Inserting in dorothy.#{table}:"
		#p "#{@sqlstring}"
		
		begin
			@conn.exec("INSERT into dorothy.#{table} values (#{@sqlstring})") 	
			rescue => e
      LOGGER.debug "DB", $!
			LOGGER.debug "DB", e.inspect
			#self.rollback
			return false
			#exit 1
		end
		
		#p "Insertion OK"
		
	end
	
	def raw_insert(table, data)
		begin
			@conn.exec("INSERT into dorothy.#{table} values (#{data})") 	
			rescue		
			LOGGER.error "DB", "#{$!}"
			#self.rollback
			return false
			#exit 1
		end
	end
	
	def select(table, column, value, column2=nil, value2=nil, column3=nil, value3=nil)
    column2&&value2 ? ( column3&&value3 ? chk = @conn.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}' AND #{column2} = '#{value2}' AND #{column3} = '#{value3}' ") : chk = @conn.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}' AND #{column2} = '#{value2}'")) : chk = @conn.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}'")

		#puts ".::WARNING #{value} already present in dorothy.#{table}".red.bold if chk
		return chk	
	end
	
	def self.escape_bytea(data)
	escaped = PGconn.escape_bytea data
	return escaped
end

def update_proto(role, ip)
	@conn.exec("UPDATE dorothy.host_roles set app_protocol = '#{proto}' where id = currval('connections_id_seq')") 
end

def set_analyzed(hash)
	@conn.exec("UPDATE dorothy.traffic_dumps set parsed = true where hash = '#{hash}'") 
end

def find_seq(seq)
	@conn.exec("SELECT currval('dorothy.#{seq}')") 
end

def malware_list
	malwares = []
	@conn.exec("SELECT samples.hash FROM dorothy.samples").each do |q|
		malwares.push q
	end
	return malwares
end

def find_pcap
	@pcaps = []
	begin
		@conn.exec("SELECT traffic_dumps.hash, traffic_dumps.pcapr_id, traffic_dumps.size, traffic_dumps.binary, traffic_dumps.parsed, samples.md5 as \"sample\", analyses.date as \"date\" FROM dorothy.traffic_dumps, dorothy.samples, dorothy.analyses WHERE analyses.traffic_dump = traffic_dumps.hash AND analyses.sample = samples.hash AND traffic_dumps.parsed = false").each do |q|
			@pcaps.push q
		end
		rescue
		LOGGER.error "DB","Error while fetching traffic_dumps table\n " + $!
	end
	
end

def find_vm
	vm = @conn.exec("SELECT id, hostname, ipaddress FROM dorothy.sandboxes where is_available is true").first
	if vm.nil?
		LOGGER.warn "DB"," At this time there are no free VM available"
		return false
  else
		@conn.exec("UPDATE dorothy.sandboxes set is_available = false where id = '#{vm["id"]}'")
		return vm["id"].to_i, vm["hostname"], vm["ipaddress"]
	end
end

def free_vm(vmid)
	r = @conn.exec("SELECT hostname FROM dorothy.sandboxes where id = '#{vmid}' AND is_available is false") 
	if !r.first.nil? #check if the issued VM is already free
		begin
			@conn.exec("UPDATE dorothy.sandboxes set is_available = true where id = '#{vmid}'")
			LOGGER.info "DB", " VM #{vmid} succesfully released"
			return true
			rescue
			LOGGER.error "DB", "An error occurred while releasing the VM"
			LOGGER.debug "DB", $!
			return false
		end
		else  
		LOGGER.warn "DB", " Dorothy is trying to release the VM #{vmid} that is already available!!"
		return false
	end
end

def vm_init
	@conn.exec("UPDATE dorothy.sandboxes set is_available = true")
	LOGGER.debug "DB", " All VM are now available"
	#TODO - revert them too?
end


end

end