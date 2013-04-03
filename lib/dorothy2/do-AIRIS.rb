#require 'net/http'
#require 'net/https'
#require 'rubygems'
#require 'rest_client'
#require 'mime/types'
#require 'colored'

module Dorothy

class AIRIS
	
	def initialize(server_url)
		#####################RETRIEVE A VALID COOKIE
		login = {:user=>"root", :pass=>"Bdigital!"}
		@resource = "#{server_url}/REST/1.0/"
		headers = { 'User-Agent'   => "Mozilla/5.0 ruby RT Client Interface 0.4.0", 'Content-Type' => "application/x-www-form-urlencoded" }
		site = RestClient::Resource.new(@resource, :headers => headers, :timeout => 120)
		data = site.post login, :headers => headers
		cookie = data.headers[:set_cookie].to_s.split('; ')[0]
		@boundary = "----xYzZY#{rand(1000000).to_s}xYzZY"
		@headers = { 'User-Agent'   => "Mozilla/5.0 ruby RT Client Interface 0.4.0", 'Content-Type' => "multipart/form-data; boundary=#@boundary", 'Cookie' => cookie }
	end
	
	def fetch_airis(dir)
		#.119 = dev 
		
		Dir.chdir(dir)
		
		ticket_list = [] 
		
		query = "(Queue = 'Incidents' OR Queue = 'Limbo' ) AND (  Status != 'close' AND Status != 'rejected' AND Status != 'shutdown')".gsub(/\s+/, "%20")
		
		site = RestClient::Resource.new(@resource, :headers => @headers)
		data = site["search/ticket?query=#{query}"].get 
		#resp, data = @http.post("/REST/1.0/search/ticket?query=#{query}",@login,@headers)
		
		
		@incidents = {}
		data.each do |line|
			#@incidents[line.split(/: /)[0].to_i] = line.split(/: /)[1]
			ticket_list.push($1.to_i) if line =~ /^([0-9]*):(.*)/
		end
		
		#puts @incidents
		LOGGER.info "AIRIS", "Query completed, #{ticket_list.length} found"
		
		threads = []
		uris = []
		
		for id in ticket_list
			threads << Thread.new(id) { |myId|
				tries = 0
				
				begin
					#puts "Quering RT ticket n.#{myId}"
					site = RestClient::Resource.new(@resource, :headers => @headers)
					data = site["ticket/#{myId}/show"].get
					rescue Exception 
					tries += 1
					LOGGER.error "AIRIS", "Error while read ticket n. #{myId}:  #{$!}"
					LOGGER.error "AIRIS", "Retry n. #{tries}" 
					retry if tries < 3
				end
				
				
				#puts "Parsing content of #{myId}"
				
				
				data.each do |line|
					if line =~ /(CF.\{Target_string\}:)(.*)/
						urls = $2.split(/,/)
						urls.each do |url|
							if url.strip =~ /\/([a-zA-Z_\-0-9]*\.exe$)/
								filename = $1
								uris.push([myId,url.strip,filename])     #uris tructure:  [airisticketId, trojanurl, filename]
							end
						end
					end
				end
				
			}
		end
		
		threads.each { |aThread|  aThread.join }
		
		return uris
	end
	
	def download_bins(uris)		
		threads = []
		downloaded = []
		uris.each do |uri|
			if !uri[1].nil? || !uri[1].empty?
				threads << Thread.new(uri) { |urId|
					tries = 0
					LOGGER.info "AIRIS", "Downloading trojan from AIRIS ticketid #{uri[0]}: #{uri[1]}"
					weburl = URI.parse(uri[1])
					begin
						response = Net::HTTP.get_response(weburl)
						File.open(uri[2], 'w') {|f| f.write(response.body) }
						LOGGER.info "AIRIS",  "File #{uri[2]} downloaded"
						downloaded.push uri
						rescue Exception 
						tries += 1
						LOGGER.error "AIRIS",  "Error while downloading #{weburl}:  #{$!}"
						LOGGER.error "AIRIS",  "Retry n. #{tries}"
						retry if tries < 3
					end
				}
			end
		end
		threads.each { |aThread|  aThread.join }
		return downloaded  #struct:  [["ticket_id", "http uri", "file name"], .., ..,]]
	end
	
	def add_comment(ticketid, comment, attachment=nil)
		#attachment = File path
		body = ""
		fields ={:id => ticketid, :Action => "comment", :Text => comment, :Attachment => attachment } 
		fields[:Text].gsub!(/\n/,"\n ") # insert a space on continuation lines.
		
		############ATTACHMENT		
		if !attachment.nil?
			filenames = fields[:Attachment].split(',')
			i = 0
			filenames.each do |v|
				filename = File.basename(v)
				mime_type = ( File.extname(filename) == ".pcap" ? "application/octet-stream" : MIME::Types.type_for(v)[0].simplified)  #Workaroubd, MIME lib for ruby doesn't support pcap MIME format yet 
				i += 1
				param_name = "attachment_#{i.to_s}"
				body << "--#@boundary\r\n"
				body << "Content-Disposition: form-data; "
				body << "name=\"#{URI.escape(param_name.to_s)}\"; "
				body << "filename=\"#{URI.escape(filename)}\"\r\n"
				body << "Content-Type: #{mime_type}\r\n\r\n"
				body << File.read(v) # oh dear, lets hope you have lots of RAM
			end
			fields[:Attachment] = filenames.map {|f| File.basename(f)}.join(',')
		end
		###
		field_array = fields.map { |k,v| "#{k}: #{v}" }
		content = field_array.join("\n") # our form
		body << "--#@boundary\r\n"
		body << "Content-Disposition: form-data; "
		body << "name=\"content\";\r\n\r\n"
		body << content << "\r\n"
		body << "--#@boundary--\r\n"
		
		
		site = RestClient::Resource.new(@resource, :headers => @headers)
		site["ticket/#{ticketid}/comment"].post body
		
	end
	
	def create_incident(fields)
		body = ""
		field_array = fields.map { |k,v| "#{k}: #{v}" }
		content = field_array.join("\n") # our form
		body << "--#@boundary\r\n"
		body << "Content-Disposition: form-data; "
		body << "name=\"content\";\r\n\r\n"
		body << content << "\r\n"
		body << "--#@boundary--\r\n"
		
		
		site = RestClient::Resource.new(@resource, :headers => @headers)
		site["ticket/new"].post body
	end
	
	def update_ticket(ticketid, fields)
		
		body = ""
		field_array = fields.map { |k,v| "#{k}: #{v}" }
		content = field_array.join("\n") # our form
		body << "--#@boundary\r\n"
		body << "Content-Disposition: form-data; "
		body << "name=\"content\";\r\n\r\n"
		body << content << "\r\n"
		body << "--#@boundary--\r\n"
		
		
		site = RestClient::Resource.new(@resource, :headers => @headers)
		site["ticket/#{ticketid}/edit"].post body
		
		
	end
end

end
