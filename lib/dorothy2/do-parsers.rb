# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

#To install on MacOSX
#Go to postgres website and download the OSX installer
#none:ruby-pg-0.7.9.2008.01.28 root# gem install ruby-pg -- --with-pg-config="/Library/PostgreSQL/9.0/bin/pg_config" --with-pgsql-lib=/Library/PostgreSQL/9.0/lib --with-pgsql-include=/Library/PostgreSQL/9.0/include
#
#To install on Debian
#apt-get install postgres-8.3
#apt-get install libpq-dev
#sudo gem install pg -- --with-pgsql-lib=/usr/lib/postgresql/8.3/lib/ --with-pg-config=/usr/bin/pg_config


#include Pcap

module DoroParser

class Mydns
	def initialize(data)
		raw = data.to_s.gsub(/(\000|\001|\002|\003|\004|\005|\006|\007|\008|\009|\010|\011|\012|\013|\014|\015|\016|\017|\018|\019|\020|\021\022|\023|\024|\025|\026|\027)/, '.')
	    @query = raw.grep(/([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}/){$&}
	end
	
	def query 
		return @query  if @query
	end
	
	def query? 
		return true if @query
	end
	
	def dns_class
		#todo
	end 
	
	def type
		#todo
	end 	
	
	def response
		#todo
	end 
end


class Parser_old
	
	def initialize(data) 
		noutf = Iconv.new('US-ASCII//TRANSLIT', 'UTF-8')
		if data and data =~ /(USER |USERHOST |PRIVMSG |PASS |NICK |JOIN |MODE |MSG |KCIK |rssr )(.*)\n/
			@irc = true
			@command = $1
			begin
				#@command2 = noutf.iconv($2).gsub(/"|'|\\/, "-")
				rescue
				@command2 = "null" 
			end
			elsif data =~ /from\W*([0-9]{1,3}(\.[0-9]{1,3}){3}).*by\W*(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}).*From:.*<(\S+)>\W*To:.*<(\S+)>.*Subject:(.*)\W*Date/m
			@mail = true
			@fromip = $1
			@by =$3
			@from = $6
			@to = $7
			@subj = $8.chomp.lstrip	
			
			
			elsif data and data =~ /^(GET|POST)\s+(\S+)/
			@http = true
			@method = $1
			@path = $2
			
		end	
	end
	
end	


class Parser 
	attr_reader :service	
	
	def self.guess(a)
	
		if a =~ /USER |USERHOST |PRIVMSG |PASS |NICK |JOIN |MODE |MSG/ 
		t = IRC.new a 
		elsif a =~ /from(.*)From(.*)Subject/m
		t = SMTP.init a
		elsif a =~ /(\d*)(.*)\n/
		t = SMTP.new a
		end

		return t
	end




class IRC 
	attr_reader :command
	attr_reader :content
	
	
	def initialize(data)
		if data =~ /(USER |USERHOST |PRIVMSG |PASS |NICK |JOIN |MODE |MSG )(.*)\n/
			noutf = Iconv.new('US-ASCII//TRANSLIT', 'UTF-8')
			@command = $1
			@content = noutf.iconv($2).gsub(/"|'|\\/, "-")    #xcode bug ->>> ")
		end
		#return true if !@command.nil?
		return self
	end
	
	
	
end	



class SMTP 
	#todo make a initialize class 
	attr_reader :hcmd
	attr_reader :hcont
	attr_accessor :body
	attr_accessor :rdata
	
	def self.body(data)
	
	email = TMail::Mail.parse(data)
	return email 
	
end

def self.header?(data)

if data =~ /(MAIL FROM: |EHLO |HELO |TO: |RSET)(.*)\n/
	return true
end

end

def self.hasbody?(data)

if data =~ /from(.*)From(.*)Subject/m
	return true
end

end

def self.response(data)

if data =~ /(\d*)(.*)\n/
	rcode = $1
	rcont = $2
	return rcode, rcont
end

end

def initialize a 
	
	if a =~ /(MAIL FROM: |EHLO |HELO |TO: |RSET)(.*)\n/
		@hcmd = $1
		@hcont = $2
	end
	
end

end

end

class Geoinfo
	attr_reader :updated
	attr_reader :country
	attr_reader :coord
	attr_reader :asn
	attr_reader :city	
	attr_reader :updated
	

	@updated = "null"
	LOCALNET = "10.10.10.0/24"
	
	
	
	def initialize(ip)
		noutf = Iconv.new('US-ASCII//TRANSLIT', 'UTF-8')
		@updated = 'null' #TODO take the creation file date of the .dat archive
		
		#year = geoip.database_info.grep(/(\S+) (\d{4})(\d{2})(\d{2})/){$2}
		#month = geoip.database_info.grep(/(\S+) (\d{4})(\d{2})(\d{2})/){$3}
		#day = geoip.database_info.grep(/(\S+) (\d{4})(\d{2})(\d{2})/){$4}
		#@updated = year.to_s + "/" + month.to_s + "/" + day.to_s	
		localnetwork = IPAddr.new(LOCALNET)
		
		if !localnetwork.include?(ip)
			
			begin
				
				geoip = GeoIP.new(GEOIP)
				geoasn = GeoIP.new(GEPASN)
				
				if geoip.country(ip)
					@city = noutf.iconv(geoip.country(ip).city_name).gsub(/"|'|\\/, "-") #xcode bug ->>> ")
					@country = geoip.country(ip).country_code2
					@coord = geoip.country(ip).latitude.to_s.gsub(/\(|\)/,'') + "," + geoip.country(ip).longitude.to_s.gsub(/\(|\)/,'')
					
					else 
					
					@city, @country, @coord = "null", "null", "null"  
					
				end
				
				@asn = (geoasn.asn(ip) ? geoasn.asn(ip).as_num.to_s.grep(/\d+/){$&}	: "null" )	
				
				rescue
				LOGGER_PARSER.fatal "GEO", "Error while fetching GeoIP dat file for IP: " + ip
				LOGGER_PARSER.fatal "GEO", "#{$!}"
				@city, @country, @coord, @asn = "null", "null", "null", "null"		
			end
			
			else 		
			@city, @country, @coord, @asn = "null", "null", "null", "null"		
			
		end
	end
	
end


class DoroHttp
	attr_reader :contype
	attr_reader :method 
	attr_reader :uri
	attr_reader :ssl
	attr_reader :size
	attr_accessor :data
	
	def initialize(flowdeep)
		@data = 'null'
		@method = (flowdeep.values('http.request.method')[0] ? flowdeep.values('http.request.method')[0].value : 'null')
		@ssl = false #TODO
		@size = (flowdeep.values('http.content.length')[0] ? flowdeep.values('http.content.length')[0].value : 'null') 
		@uri = (flowdeep.values('http.request.uri')[0] ? flowdeep.values('http.request.uri')[0].value : 'null' )					
		@contype = (flowdeep.values('http.content.type')[0] ? flowdeep.values('http.content.type')[0].value : 'null')
	end
	
end

class DoroDNS
	attr_accessor :dns
	attr_accessor :ttl
	attr_accessor :name
	attr_accessor :type
	attr_accessor :type_i
	attr_accessor :cls
	attr_accessor :cls_i
	attr_accessor :address
	attr_accessor :data
	
	def initialize(c)
		@dns = Net::DNS::Packet::parse(c)
		if qry? #is a query
			q = @dns.question.first
			@cls_i = q.qClass			#Net::DNS::Question.parse(c[12..offset]).qClass
			@name = q.qName
			@type_i = q.qType
			@ttl = 'null'
			@address = 'null'
			@data = 'null'
			
			elsif !@dns.answer.empty? #contain an asnwer
			#TODO only the first answer is parsed
			a = @dns.answer.each.first
			@ttl = a.ttl
			@name = a.name
			
		    @type = a.type
			@type_i = Net::DNS::RR::Types.new @type
			
			
			@cls = a.cls
			@cls_i = Net::DNS::RR::Classes.new @cls 	
			
			
			case @type 
				
				when "A"
				@address = @dns.answer.each.first.address	
				@data = 'null'
				
				when "AAAA"
				@address = @dns.answer.each.first.address	
				@data = 'null'
				
				when "MX" then
				
				@data = @dns.answer.each.first.exchange 
				@address = 'null'
				
				when "CNAME" then
				
				@data = @dns.answer.each.first.cname
				@address = 'null'
				
				else 
				
				@address = 'null'
				@data = 'null'
				
			end
		end
		
	end
	
	
	def qry?
		@dns.answer.empty?
	end
	
end

class DoroFile
	attr_accessor :sha2
	attr_accessor :cont
	attr_reader :path
	attr_reader :date
	attr_accessor :size
	
	def initialize(hash)
		repo = "./downloads"
		@path = "#{repo}/#{hash}.exe"
		@date = Time.new.strftime("%m/%d/%y %H:%M:%S")
	end
	
	def self.sha2(content)
	@sha2 = Digest::SHA2.new
	@sha2 << content
end
end


class Doroxtractr < Mu::Xtractr    #PcaprLocal::Xtractr.new
	
	#def lol(id)
	#	self.create "http://172.20.250.13:8080/pcaps/1/pcap/#{id}"
	#end
	
	
	def summaryhttp(fast=0, v=0)
		ids = []
		self.flows('flow.service:HTTP').each { |flow|
			method = self.flows("flow.id:#{flow.id}").values('http.request.method')[0].value
			if fast == 0
				puts "#{flow.id} #{flow.src.address} > #{flow.dst.address} - #{method} -  #{flow.stream.flow.contents.first.body.length}" 
				else
				puts "#{flow.id} #{flow.src.address} > #{flow.dst.address} - #{method}"
			end
			ids.push(flow.id)
		}
		return ids
	end
	
	def flowinfo(id)
		f = self.flows("flow.id:#{id}").first.inspect
		f << self.flows("flow.id:#{id}").first.time.to_s
		return f
	end
	
	#Find the HTTP requests made by the host (Zeus uses it to send stolen data to its dropzone)
	#The biggest post refers to the STATS one (by default is sent every 20 min)
	#the smallest post refers to the LOG one (by default is sent every minute)
	#the biggest GET refers to the Configuration file downloaded by the Zeus C&C
	def findzeusdata(re, type, cc='192.168.10.3')
		flowids = {}
		self.flows("flow.service:HTTP flow.dst: #{cc}").each do |flow|
			method = self.flows("flow.id:#{flow.id}").values('http.request.method')[0].value
			flowids[flow.id] = flow.stream.flow.contents.first.body.length if method =~ /#{Regexp.escape(re)}/
		end
		if type == "ping"
			return flowids.sort {|a,b| a[1]<=>b[1]}.first
			elsif type == "stat" || type == "conf"
			return flowids.sort {|a,b| a[1]<=>b[1]}.last
			else
			puts "Error, choose one argument from: ping, stat, conf"
			return 1
		end
	end
	
	
	#Find the HTTP GET request made by the host (Zeus uses it to send stolen data to its dropzone)
	#Is the first get request made to the C&C [!?]
	def findconfget
		self.flows("flow.service:HTTP flow.dst: #{cc}")
	end
	
	def summaryhttpmethod(re, fast=0)
		self.flows('flow.service:HTTP').each { |flow|
			flowdeep = self.flows("flow.id:#{flow.id}")
			if fast == 0
				puts "#{flow.id} #{flow.src.address} > #{flow.dst.address} - #{flow.stream.flow.contents.first.body.length}" if flowdeep.values('http.request.method')[0] && flowdeep.values('http.request.method')[0].value =~ /#{Regexp.escape(re)}/
				else
				puts "#{flow.id} #{flow.src.address} > #{flow.dst.address}" if flowdeep.values('http.request.method')[0] && flowdeep.values('http.request.method')[0].value =~ /#{Regexp.escape(re)}/
			end
		}
	end
	
	def flowsummary(verbose=0)
		self.flows.each { |flow|
			flowdeep = self.flows("flow.id:#{flow.id}")
			if verbose == 1
				puts "#{flow.id}: #{flow.time} : #{flow.src.address} > #{flow.dst.address} - #{flow.packets} - #{flow.bytes} - #{flow.duration} - #{flow.title}" 
				else
				puts "| #{flow.id}: #{flow.src.address} > #{flow.service.name} > #{flow.dst.address} : #{flow.title}"
			end
		}
	end
	
	
	def summaryport(port)
		self.flows("flow.dport:#{port}").each do |f|
			f.contents.each do |c|
				puts "#{f.id}: #{flow.id} #{flow.src.address} > #{flow.dst.address} #{f.title} : #{c.body.length}"
			end
		end
	end
	
	def flowgrep(id, re)
		self.flows("flow.id:#{id}").each do |f|
			@t = false	
			f.stream.each do |mex|
				if mex.bytes =~ /#{re}/
					puts "#{f.id}: > #{f.dst.address} - #{$1}" 
					@t = true
				end
			end
		end
		return @t
	end
	
	def streamdata(id)
		data = []
		self.flows("flow.id:#{id}").each do |f|
			f.stream.each do |mex|
				t = [mex.bytes, mex.dir]
				data.push t 
			end
		end
		return data
	end
	
	
	
	
	#Retrieve the content of a specified flow-ID
	def flowcontent(id)
		body = ""
		self.flows("flow.id:#{id}").each do |flow|
			flow.contents.each do |c|
				body << c.body
			end
		end
		return body
	end
	
end

end