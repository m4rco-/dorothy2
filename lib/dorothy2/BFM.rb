# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.


#############################
### BINARY FETCHER MODULE ###
#############################

#The BFM module is in charge of retreiving the binary from the sources configured in the sources.yml file.
#It receive the source hash, and return the downloaded binaries objects.





module Dorothy

  class DorothyFetcher
    attr_reader :added

    #Source_arr is an array e.g.: ["webgui", {"type"=>"system", "localdir"=>"/Users/akira/Downloads/doroth2_1.9.3_mail/opt/bins/webgui", "typeid"=>1}]
    def initialize(source_arr)
      ndownloaded = 0

      @added = Hash.new
      source = source_arr[1]      #source_arr[1] is a hash

      source["priority"] ||= 0
      source["profile"] ||= "default"


      case source["type"]

        when "ssh" then
          #file = "/opt/dionaea/var/dionaea/binaries/"
          #puts "Start to download malware"

          files = []

          begin
            Net::SSH.start(source["ip"], source["username"], :password => source["pass"], :port => source["port"]) do |ssh|
              ssh.scp.download!(source["remotedir"],source["localdir"], :recursive => true) do |ch, name, sent, total|
                unless files.include? "#{source["localdir"]}/" + File.basename(name)
                  ndownloaded += 1
                  files.push "#{source["localdir"]}/" + File.basename(name)
                end
                #		print "#{File.basename(name)}: #{sent}/#{total}\r"
                #		$stdout.flush
              end
              LOGGER.info "BFM", "#{ndownloaded} files downloaded"
            end

          rescue => e
            LOGGER.error "BFM", "An error occurred while downloading malwares from honeypot sensor: " + $!
            LOGGER.error "BFM", "Error: #{$!}, #{e.inspect}, #{e.backtrace}"
          end

          #DIRTY WORKAROUND for scp-ing only files without directory
          FileUtils.mv(Dir.glob(source["localdir"] + "/binaries/*"), source["localdir"])
          Dir.rmdir(source["localdir"] + "/binaries")


          begin
            unless DoroSettings.env[:testmode]
              Net::SSH.start(source["host"], source["user"], :password => source["pass"], :port => source["port"]) do |ssh|
                ssh.exec "mv #{source["remotedir"]}/* #{source["remotedir"]}/../analyzed "
              end
            end
          rescue
            LOGGER.error "BFM", "An error occurred while erasing parsed malwares in the honeypot sensor: " + $!
          end

          files.each do |f|
            begin
              @added = QueueManager.add(f, source_arr[0], source["profile"], source["priority"])
            rescue
              LOGGER.error "BFM", "Error while adding the bin to the queue, skipping."
              LOGGER.debug "BFM", $!
              next
            end
          end


        #Thanks to Salvatore Gervino who made the first PoC of this source-module: http://www.honeynet.it/wp-content/uploads/Mentored_Projects/salvatore_gervino-dorothy2_email.pdf
        when "mail" then

          @db = Insertdb.new

          account = {:address=>source["host"],  :username=>source["username"],
                     :password=>source["password"], :port=>source["port"], :ssl=>source["enable_ssl"], :n_emails => source["n_emails"] , :delete_once_downloaded => source["delete_once_downloaded"]}


          mailer = Dorothy::Mailer.new(account)
          begin
            emails = mailer.get_emails

            emails.each do |email|

              LOGGER.debug "BFM", "Analyzing email: #{email.date} - #{email.from_addrs[0]} - #{email.subject} - #{email.to_addrs[0]}"


              unless email.attachments.empty?
                mail_id = @db.push_email_data(email)

                attachment_content_type = Mail::ContentTypeElement.new(email.attachments.first.content_type)
                #if the attachment is a forwarded email, treat the attachment as the original email
                if attachment_content_type.main_type == 'message'

                  LOGGER.info "BFM", "Forwarded email from #{email.from.first} found"
                  email = mailer.read_from_string email.attachments.first.body.decoded
                  mail_id = @db.push_email_data(email, mail_id)

                end


                email.attachments.each do | attachment |
                  LOGGER.info "BFM", "Attachment found: #{attachment.filename} "
                  bin = source["localdir"] + "/" + Digest::MD5.hexdigest(attachment.body.decoded) + "_" + attachment.filename
                  Util.write( bin, attachment.body.decoded)
                  id = QueueManager.add(bin, source_arr[0],source["profile"], source["priority"], mail_id)
                  @added.store(id,[bin, source["priority"], source["profile"], source_arr[0]])
                end
              end

            end  #end for
            @db.close
            LOGGER.debug "BFM", "Analyzing email: End "
          rescue => e
            LOGGER.error "BFM", "Error while adding the bin to the queue, skipping. #{$!}"
            LOGGER.debug "DB", e.backtrace
          end

        when "system" then
          empty = true
          Dir.foreach(source["localdir"]) do |file|
            bin = source["localdir"] + "/" + file
            next if File.directory?(bin)

            begin
              id = QueueManager.add(bin, source_arr[0], source["profile"], source["priority"])
              empty = false
              @added.store(id,[bin, source["priority"], source["profile"], source_arr[0]])

            rescue
              LOGGER.error "BFM", "Error while adding the bin to the queue, skipping."
              LOGGER.debug "BFM", $!
              next
            end

          end
          LOGGER.debug "BFM", "No binaries were found in the selected source" if empty
        else
          LOGGER.fatal "BFM", "Source type #{source["type"]} is not yet configured"
      end
    end

    #Expects an Hash as input
    def self.loader(sources, daemon=false)

      infinite = true


      begin
        while infinite  #infinite loop
          sources.each do |sname|
            #skip if it is webgui
            next if sname.first == 'webgui'

            LOGGER.debug "BFM", "Start to fetch binaries from #{sname.first.yellow} @ #{sname[1]["localdir"]}"

            added = self.new(sname).added
            LOGGER.info "BFM", "#{added.size.to_s.yellow} binaries retreived from #{sname.first.yellow}"

            added.each do |b|
              LOGGER.debug "BFM", "#{b[0]}\t#{File.basename(b[1][0])}\t#{b[1][3]}"
            end

          end
          if daemon
            LOGGER.info "BFM", "SLEEPING 10"
            sleep DoroSettings.bfm[:sleeptime].to_i
          end
          infinite = daemon
        end

      rescue SignalException #, RuntimeError
        LOGGER.warn "BFM", "SIGINT".red + " Catched [1], exiting gracefully."
      end
    end

  end

end







