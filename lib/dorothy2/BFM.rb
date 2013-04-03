###########################
###BINARY FETCHER MODULE###
###					          	###
###########################

module Dorothy


class DorothyFetcher
  attr_reader :bins


  def initialize(source)  #source struct: Hash, {"honeypot" => {:dir => "#{HOME}/bins/honeypot", :typeid=> 0}, ...}
    ndownloaded = 0
    skey = source.keys.to_s
    @bins = []
    case skey
      when "airis" then
        LOGGER.info "BFM", " Fetching trojan from ----> AIRIS"
        airis = AIRIS.new(AIRIS_URL)
        ticket_uris = filter_analyzed airis.fetch_airis(source[skey][:dir]) ##uris structure: array of array [[airisticketId, trojanurl, filename], .. ]

        airis_bins = airis.download_bins(ticket_uris) #bins struct: array of array  [["ticket_id", "http uri", "file name"], .., ..,]]


        airis_bins.each do |abin|

          file = source[skey][:dir] + "/" + 	abin[2]

          bin = Loadmalw.new(file)
          bin.sourceinfo = abin[0]

          samplevalues = [bin.sha, bin.size, bin.dbtype, bin.dir_bin, file, bin.md5, bin.type ]
          sighvalues = [bin.sha, source[skey][:typeid], bin.ctime, "null"]
          airisvalues = [abin[0], bin.sha, abin[1]]
          next unless updatedb(samplevalues, sighvalues, airisvalues)
          @bins.push bin

        end

        LOGGER.info "BFM", " Downloaded n. #{airis_bins.length} malwares"

      when "honeypot" then
        LOGGER.info "BFM", " Fetching trojan from ----> Honeypot"
        file = "/opt/dionaea/var/dionaea/binaries/"

        #puts "Start to download malware"

        files = []
        #Dir.chdir(source[skey][:dir])

        begin
          Net::SSH.start(HPSERVER, HPUSER, :password => HPPASS, :port => 3022) do |ssh|
            ssh.scp.download!(file,source[skey][:dir], :recursive => true) do |ch, name, sent, total|
              unless files.include? "#{source[skey][:dir]}/" + File.basename(name)
                ndownloaded += 1
                files.push "#{source[skey][:dir]}/" + File.basename(name)
                #			puts ""
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

        FileUtils.mv(Dir.glob(source[skey][:dir] + "/binaries/*"), source[skey][:dir])
        Dir.rmdir(source[skey][:dir] + "/binaries")


        begin

          unless TESTMODE
            Net::SSH.start(HPSERVER, HPUSER, :password => HPPASS, :port => 3022) do |ssh|
              ssh.exec "mv /opt/dionaea/var/dionaea/binaries/* /opt/dionaea/var/dionaea/analyzed/ "
            end
          end

        rescue
          LOGGER.error "BFM", "An error occurred while erasing parsed malwares in the honeypot sensor: " + $!
        end

        files.each do |f|
          next unless load_malw(f, source[skey][:typeid])
        end

      when "manual" then
        LOGGER.info "BFM", " Fetching trojan from ----> filesystem: " + source[skey][:dir]
        Dir.foreach(source[skey][:dir]) do |file|
          bin = source[skey][:dir] + "/" + file
          next if File.directory?(bin) || !load_malw(bin,source[skey][:typeid])
        end

      when "honeypot2" then
        LOGGER.info "BFM", " Fetching trojan from ----> honeypot2 (rsync): " + source[skey][:dir]
        Dir.foreach(source[skey][:dir]) do |file|
          bin = source[skey][:dir] + "/" + file
          next if File.directory?(bin) || !load_malw(bin,source[skey][:typeid])
        end

      else
        LOGGER.fatal "BFM", " Source #{skey} is not yet configured"
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

    samplevalues = [bin.sha, bin.size, bin.dbtype, bin.dir_bin, filename, bin.md5, bin.type ]
    sighvalues = [bin.sha, typeid, bin.ctime, "null"]

    return false unless updatedb(samplevalues, sighvalues)
      #FileUtils.rm(bin.binpath)
    @bins.push bin
  end



  def filter_analyzed(ticketlist)
    db = Insertdb.new

    ticketlist.each do |ticket|

      ticketid, uri, filename = ticket

      r = db.select("airis_tickets", "ticket_id", ticketid, "uri", uri)

      if r.one?
        LOGGER.warn "AIRIS", " Binary #{filename} from #{ticketid} has been already downloaded"
        ticketlist.delete ticket
      end

    end
    return ticketlist
  end


  def updatedb(samplevalues, sighvalues, airisvalues=nil)
    insertdb = Insertdb.new
    insertdb.begin_t

    unless insertdb.select("samples", "hash", samplevalues[0]).one?  #is bin.sha already present in my db?
      unless insertdb.insert("samples", samplevalues)             #no it isn't, insert it
        LOGGER.fatal "BFM", " ERROR-DB, skipping binary"
        insertdb.rollback
        return false
      end

    else                                                          #yes it is, don't insert in sample table
      date = insertdb.select("sightings", "sample", samplevalues[0]).first["date"]
      LOGGER.warn "BFM", " The binary #{samplevalues[0]} has been already added on #{date}"
      #return false
    end


    unless insertdb.select("sightings", "sample", samplevalues[0], "date", sighvalues[2], "sensor", sighvalues[1]).one?              #but do insert into sighting one (if the sampe tuple doesn't exist already)
      insertdb.insert("sightings", sighvalues)
      else return false
    end      #explanation: I don't want to insert/analyze the same malware but I do want to insert the sighting value anyway ("the malware X has been downloaded 1 time but has been spoted 32 times")

    unless airisvalues.nil?

      unless insertdb.select("airis_tickets", "ticket_id", airisvalues[0], "uri", airisvalues[2]).one?
        insertdb.insert("airis_tickets", airisvalues)
        else return false
      end

    end

    insertdb.commit

  end



end

end







