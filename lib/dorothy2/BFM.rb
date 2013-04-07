###########################
###BINARY FETCHER MODULE###
###					          	###
###########################

module Dorothy


class DorothyFetcher
  attr_reader :bins


  def initialize(source)  #source struct: Hash, {:dir => "#{HOME}/bins/honeypot", :typeid=> 0 ..}
    ndownloaded = 0

    @bins = []
    #case source.honeypot1[:type]

    case source["type"]

      when "ssh" then
        LOGGER.info "BFM", " Fetching trojan from ----> Honeypot"
        #file = "/opt/dionaea/var/dionaea/binaries/"

        #puts "Start to download malware"

        files = []

        begin
          Net::SSH.start(source["ip"], source["user"], :password => source["pass"], :port => source["port"]) do |ssh|
            ssh.scp.download!(source["remotedir"],source["localdir"], :recursive => true) do |ch, name, sent, total|
              unless files.include? "#{source["localdir"]}/" + File.basename(name)
                ndownloaded += 1
                files.push "#{source["localdir"]}/" + File.basename(name)
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

        FileUtils.mv(Dir.glob(source["localdir"] + "/binaries/*"), source["localdir"])
        Dir.rmdir(source["localdir"] + "/binaries")


        begin

          unless TESTMODE
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
        LOGGER.info "BFM", " Fetching trojan from > filesystem: " + source["localdir"]
        Dir.foreach(source["localdir"]) do |file|
          bin = source["localdir"] + "/" + file
          next if File.directory?(bin) || !load_malw(bin,source["typeid"])



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

    ticketlist.each do |ticket|

      ticketid, uri, filename = ticket

      r = Insertdb.select("airis_tickets", "ticket_id", ticketid, "uri", uri)

      if r.one?
        LOGGER.warn "AIRIS", " Binary #{filename} from #{ticketid} has been already downloaded"
        ticketlist.delete ticket
      end

    end
    return ticketlist
  end


  def updatedb(samplevalues, sighvalues, airisvalues=nil)

    unless Insertdb.select("samples", "hash", samplevalues[0]).one?  #is bin.sha already present in my db?
      unless Insertdb.insert("samples", samplevalues)             #no it isn't, insert it
        LOGGER.fatal "BFM", " ERROR-DB, skipping binary"
        Insertdb.rollback
        return false
      end

    else                                                          #yes it is, don't insert in sample table
      date = Insertdb.select("sightings", "sample", samplevalues[0]).first["date"]
      LOGGER.warn "BFM", " The binary #{samplevalues[0]} has been already added on #{date}"
      #return false
    end


    unless Insertdb.select("sightings", "sample", samplevalues[0], "date", sighvalues[2], "sensor", sighvalues[1]).one?              #but do insert into sighting one (if the sampe tuple doesn't exist already)
      Insertdb.insert("sightings", sighvalues)
    else return false
    end      #explanation: I don't want to insert/analyze the same malware but I do want to insert the sighting value anyway ("the malware X has been downloaded 1 time but has been spoted 32 times")

    unless airisvalues.nil?

      unless Insertdb.select("airis_tickets", "ticket_id", airisvalues[0], "uri", airisvalues[2]).one?
        Insertdb.insert("airis_tickets", airisvalues)
        else return false
      end

    end

    true

  end



end

end







