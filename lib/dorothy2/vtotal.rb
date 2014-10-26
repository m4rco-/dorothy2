# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

module Dorothy

module Vtotal
  extend self

  def check_hash(hash)
    @api_key = DoroSettings.virustotal[:vtapikey]

    scans = Uirusu::VTFile.query_report(@api_key, hash)
    if (scans["response_code"] == 1 )

      positive = ( scans["positives"] > 0 ? true : false  )
      @rate = scans["positives"].to_s + "/" + scans["total"].to_s
      @permalink = (scans["permalink"] != "-" ? scans["permalink"] : "null")
      @result_date = scans["scan_date"]
      @results = scans["scans"]


      return {:rate => @rate, :link => @permalink, :date => @result_date, :results => @results, :positive => positive}

    else
      LOGGER.error "VTOTAL", scans["verbose_msg"]
      return false
    end
  end


	def analyse_file(file)
		f = File.open(file, 'r')
		begin
			results = RestClient.post 'https://www.virustotal.com/vtapi/v2/file/scan' , { :key => @api_key, :file => f}
			parsed = JSON.parse(results)
			LOGGER.info "VTOTAL]", " Ok, received with scan id " + parsed["scan_id"] if parsed["response_code"]
			#puts "[VTOTAL] ".yellow + parsed["verbose_msg"]
			@scanid = parsed["scan_id"] 
			rescue
			LOGGER.error "VTOTAL", "An error accurred while quering Virustotal"
			LOGGER.debug "DEBUG", "#{$!}"
		end
		return @scanid 
  end



	
	
	def get_report(id)
		begin
			report = RestClient.post 'https://www.virustotal.com/vtapi/v2/file/report' , { :resource => id.to_s, :key => @api_key }
			rescue
			LOGGER.error "VTOTAL", "An error accurred while quering Virustotal"
			LOGGER.debug "DEBUG", "#{$!}"
		end
		
		if !report.empty?
			
			parsed = JSON.parse(report)
			
			if (parsed["response_code"] == 1 )
				if (parsed["scans"]["McAfee"]["detected"] == true ) 
					@rate = parsed["positives"].to_s + "/" + parsed["total"].to_s
					@family = parsed["scans"]["McAfee"]["result"]
					@permalink = (parsed["permalink"] != "-" ? parsed["permalink"] : "null")
					@vendor = "McAfee" #TODO Move to config file!
					@updated = (parsed["scans"]["McAfee"]["update"] != "-" ? parsed["scans"]["McAfee"]["update"] : "null")
					@version = (parsed["scans"]["McAfee"]["version"] != "-" ? parsed["scans"]["McAfee"]["version"] : "null")
					@detected = true
					else #not detected by McAfee
					@rate = parsed["positives"].to_s + "/" + parsed["total"].to_s
					@family = "Unknown"
					@permalink = "null"
					@vendor = "McAfee" #TODO Move to config file!
					@updated = "null" 
					@version = "null"
					@detected = false
				end
				else
				LOGGER.error "VTOTAL", parsed["verbose_msg"]
				return false
			end
			else
			LOGGER.error "VTOTAL", "No data received "
			return false			
		end
		return parsed
	end
	
end

end
