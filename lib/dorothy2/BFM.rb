# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.


###########################
###BINARY FETCHER MODULE###
###					          	###
###########################
#The BFM module is in charge of retreiving the binary from the sources configured in the sources.yml file.
#It receive the source hash, and return the downloaded binaries objects.
module Dorothy

  class DorothyFetcher
    attr_reader :bins

    #Source struct: Hash, {:dir => "#{HOME}/bins/honeypot", :typeid=> 0 ..}
    def initialize(source)
      ndownloaded = 0

      @bins = []
      #case source.honeypot1[:type]

      case source["type"]

        when "ssh" then
          LOGGER.info "BFM", " Fetching trojan from > Honeypot"
          #file = "/opt/dionaea/var/dionaea/binaries/"
          #puts "Start to download malware"

          files = []

          begin
            Net::SSH.start(source["ip"], source["user"], :password => source["pass"], :port => source["port"]) do |ssh|
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
              Net::SSH.start(source["ip"], source["user"], :password => source["pass"], :port => source["port"]) do |ssh|
                ssh.exec "mv #{source["remotedir"]}/* #{source["remotedir"]}/../analyzed "
              end
            end
          rescue
            LOGGER.error "BFM", "An error occurred while erasing parsed malwares in the honeypot sensor: " + $!
          end

          files.each do |f|
            next unless load_malw(f, source[skey][:typeid])
          end

        when "system" then
          LOGGER.info "BFM", "Fetching trojan from > filesystem: " + source["localdir"]
          empty = true
          Dir.foreach(source["localdir"]) do |file|
            bin = source["localdir"] + "/" + file
            next if File.directory?(bin) || !load_malw(bin,source["typeid"])
            empty = false
          end
          LOGGER.warn "BFM", "There are no files to analyze in the selected source" if empty
        else
          LOGGER.fatal "BFM", "Source #{skey} is not yet configured"
      end
    end

    private
    def load_malw(f, typeid, sourceinfo = nil)

      filename = File.basename f
      bin = Loadmalw.new(f)
      if bin.size == 0  || bin.sha.empty?
        LOGGER.warn "BFM", "Warning - Empty file #{filename}, deleting and skipping.."
        FileUtils.rm bin.binpath
        return false
      end

      samplevalues = [bin.sha, bin.size, bin.dir_bin, filename, bin.md5, bin.type ]
      sighvalues = [bin.sha, typeid, bin.ctime, "null"]

      begin
        updatedb(samplevalues, sighvalues)
      rescue => e
        LOGGER.error "DB", $!
        LOGGER.debug "DB", e.inspect
        return false
      end

      #FileUtils.rm(bin.binpath)
      @bins.push bin
    end



    def updatedb(samplevalues, sighvalues, airisvalues=nil)

      db = Insertdb.new
      db.begin_t

      unless db.select("samples", "sha256", samplevalues[0]).one?  #is bin.sha already present in my db?
        raise "A DB error occurred" unless db.insert("samples", samplevalues)             #no it isn't, insert it

      else                                                          #yes it is, don't insert in sample table
        date = db.select("sightings", "sample", samplevalues[0]).first["date"]
        LOGGER.warn "BFM", " The binary #{samplevalues[0]} has been already added on #{date}"
      end

      raise "A DB error occurred" unless db.insert("sightings", sighvalues)

      # explanation: I don't want to insert/analyze the same malware but I do want to
      # insert the sighting value anyway ("the malware X has been downloaded 1 time but
      # has been spoted 32 times")

      db.commit
      db.close
      true

    end



  end

end







