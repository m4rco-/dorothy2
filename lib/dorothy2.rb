# Copyright (C) 2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

##for irb debug:
##from $home, irb and :
##load 'lib/dorothy2.rb'; include Dorothy; LOGGER = DoroLogger.new(STDOUT, "weekly"); DoroSettings.load!('etc/dorothy.yml')
$LOAD_PATH.unshift '/opt/local/lib/ruby/gems/1.8/gems/ruby-filemagic-0.4.2/lib'

require 'net/ssh'
require 'net/scp'
require 'trollop'
require 'fileutils'
require 'rest_client'
require 'mime/types'
require 'colored'
require 'logger'
require 'pg'
require 'filemagic'
require 'rbvmomi'
require 'timeout'
require 'virustotal'
require 'ftools' #deprecated at ruby 1.9 !!!
require 'filemagic'
require 'md5'

require File.dirname(__FILE__) + '/dorothy2/do-init'
require File.dirname(__FILE__) + '/dorothy2/Settings'
require File.dirname(__FILE__) + '/dorothy2/deep_symbolize'

require File.dirname(__FILE__) + '/dorothy2/environment'

require File.dirname(__FILE__) + '/dorothy2/vtotal'
require File.dirname(__FILE__) + '/dorothy2/MAM'
require File.dirname(__FILE__) + '/dorothy2/BFM'
require File.dirname(__FILE__) + '/dorothy2/do-utils'
require File.dirname(__FILE__) + '/dorothy2/do-logger'

module Dorothy

def get_time
  time = Time.new
  time.utc.strftime("%Y-%m-%d %H:%M:%S")
end


def start_analysis(bins, daemon)
  bins.each do |bin|
    next unless check_support(bin)
    scan(bin) unless DoroSettings.env[:testmode]   #avoid to stress VT if we are just testing
    @analysis_threads << Thread.new(bin.filename){
      db = Insertdb.new
      sleep 30 while !(guestvm = db.find_vm)  #guestvm struct: array ["sandbox id", "sandbox name", "ipaddress", "user", "password"]
      analyze(bin, guestvm)
      db.free_vm(guestvm[0])
      db.close
    }
  end
end


def check_support(bin)
  if bin.extension == ".exe" || bin.extension == ".bat"
    true
    else
    LOGGER.warn("SANDBOX", "File #{bin.filename} actually not supported, skipping\n" + "	Filtype: #{bin.type}") # if VERBOSE
    FileUtils.cp(bin.binpath,File.dirname(bin.binpath) + "/not_supported") #mv?
    FileUtils.rm(bin.binpath) ## mv?
    return false
  end
end

###ANALYZE THE SOURCE
def analyze(bin, guestvm)

  #RESERVING AN ANALYSIS ID
  db = Insertdb.new
  anal_id = db.get_anal_id

  #source.each do |sname, sinfo|

  #Dir.chdir(sinfo[:dir])

  #set home vars
  sample_home = DoroSettings.env[:analysis_dir] + "/#{anal_id}"
  bin.dir_bin = "#{sample_home}/bin/"
  bin.dir_pcap = "#{sample_home}/pcap/"
  bin.dir_screens = "#{sample_home}/screens/"
  bin.dir_downloads = "#{sample_home}/downloads/"


  LOGGER.info "SANDBOX", "VM#{guestvm[0]} ".yellow + "Analyzing binary #{bin.filename}"

  begin
    #crate dir structure in analisys home
    if !File.directory?(sample_home)
      LOGGER.info "MAM","VM#{guestvm[0]} ".yellow + "Creating DIRS"
      Dir.mkdir sample_home
      Dir.mkdir bin.dir_bin
      Dir.mkdir bin.dir_pcap
      Dir.mkdir bin.dir_screens
      Dir.mkdir bin.dir_downloads

      if VERBOSE
        LOGGER.debug "MAM", sample_home
        LOGGER.debug "MAM",bin.dir_bin
        LOGGER.debug "MAM",bin.dir_pcap
        LOGGER.debug "MAM",bin.dir_screens
      end

    else
      LOGGER.warn "SANDBOX","Malware #{bin.md5} sample_home already present, WTF!? Skipping.."
      #print "\n"
      return false
    end



    FileUtils.cp(bin.binpath,bin.dir_bin)  # mv?


    #Creating a new MAM object for managing the SandBox VM
    LOGGER.info "MAM","VM#{guestvm[0]} ".yellow + "Connecting to ESX Server #{DoroSettings.esx[:host]}"

    mam = DorothyMAM.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4])


    #Copy File to VM
    r = 0

    begin
      mam.check_internet
    rescue
      if r <= 2
        r = r+1
        LOGGER.warn "SANDBOX","VM#{guestvm[0]}".yellow + " GUESTOS Connection problem to Internet, retry n. #{r}/3"
        sleep 20
        retry
      end
      LOGGER.error "SANDBOX", "VM#{guestvm[0]}".yellow + " Guest system is not able to connect to internet"
      r = 0
      retry
    end



    LOGGER.info "MAM","VM#{guestvm[0]} ".yellow + "Copying #{bin.md5} to VM"

    filecontent = File.open(bin.binpath, "rb") { |byte| byte.read } #load filebinary
    mam.copy_file("#{bin.md5}#{bin.extension}",filecontent)

    #Start Sniffer
    dumpname = bin.md5
    pid = @nam.start_sniffer(guestvm[2],DoroSettings.nam[:interface], dumpname, DoroSettings.nam[:pcaphome]) #dumpname = vmfile.pcap
    LOGGER.info "NAM","VM#{guestvm[0]} ".yellow + "Start sniffing module"
    LOGGER.debug "NAM","VM#{guestvm[0]} ".yellow + "Tcpdump instance #{pid} started" if VERBOSE

    sleep 5

    begin
      #Execute File into VM
      LOGGER.info "MAM","VM#{guestvm[0]} ".yellow + "Executing #{bin.md5} File into VM"

      guestpid = mam.exec_file("#{bin.md5}#{bin.extension}")

      LOGGER.debug "MAM","VM#{guestvm[0]} ".yellow + "Program executed with PID #{guestpid}" if VERBOSE


      LOGGER.info "MAM","VM#{guestvm[0]}".yellow + " Sleeping #{DoroSettings.sandbox[:sleeptime]} seconds".yellow

      #wait n seconds

      (1..DoroSettings.sandbox[:sleeptime]).each do |i|
        @screenshot1 = mam.screenshot if i == DoroSettings.sandbox[:screen1time]
        @screenshot2 = mam.screenshot if i == DoroSettings.sandbox[:screen2time]
        #t = "."*i
        #print "VM#{guestvm[0]}Sleeping #{SLEEPTIME} seconds".yellow  + " #{t}\r"
        #print "VM#{guestvm[0]}Sleeping #{SLEEPTIME} seconds".yellow + " #{t}" + " [Done]\n".green if i == SLEEPTIME
        sleep 1
        $stdout.flush
      end



      #Stopt Sniffer
      LOGGER.info "NAM", "VM#{guestvm[0]} ".yellow + "Stopping sniffing module " + pid
      @nam.stop_sniffer(pid)

      #Stop/Revert VM
      LOGGER.info "MAM","VM#{guestvm[0]} ".yellow + "Reverting VM"
      mam.revert_vm

      sleep 5

    rescue

      LOGGER.error "SANDBOX", "VM#{guestvm[0]} - An error occourred while executing the file into the vm:\n  #{$!}"

      LOGGER.warn "SANDBOX", "VM#{guestvm[0]} ".red + "[RECOVER] Stopping sniffing module ".yellow + pid
      @nam.stop_sniffer(pid)

      LOGGER.warn "SANDBOX", "VM#{guestvm[0]} ".red + "[RECOVER] Reverting VM".yellow
      mam.revert_vm
      sleep 5

      LOGGER.warn "SANDBOX", "VM#{guestvm[0]} ".red + "[RECOVER] Recovering finished, skipping to next binaries".yellow
      FileUtils.rm_r(sample_home)
      return false

    end


    #Downloading PCAP
    LOGGER.info "NAM", "VM#{guestvm[0]} ".yellow + "Downloading #{dumpname}.pcap to #{bin.dir_pcap}"
    #t = DoroSettings.nam[:pcaphome] + "/" + dumpname + ".pcap"
    Ssh.download(DoroSettings.nam[:host], DoroSettings.nam[:user],DoroSettings.nam[:pass], DoroSettings.nam[:pcaphome] + "/" + dumpname + ".pcap", bin.dir_pcap)

    #Downloading Screenshots from esx
    LOGGER.info "NAM", "VM#{guestvm[0]} ".yellow + "Downloading Screenshots"
    Ssh.download(DoroSettings.esx[:host],DoroSettings.esx[:user], DoroSettings.esx[:pass], @screenshot1, bin.dir_screens)
    Ssh.download(DoroSettings.esx[:host],DoroSettings.esx[:user], DoroSettings.esx[:pass], @screenshot2, bin.dir_screens)


    #####################
    #UPDATE DOROTHIBE DB#
    #####################

    pcapfile =  bin.dir_pcap + dumpname + ".pcap"
    dump = Loadmalw.new(pcapfile)

    pcaprpath = bin.md5 + "/pcap/" + dump.filename
    pcaprid = Loadmalw.calc_pcaprid(pcaprpath, dump.size)

    LOGGER.debug "NAM", "VM#{guestvm[0]} ".yellow + "Pcaprid: " + pcaprid if VERBOSE

    empty_pcap = false

    if dump.size <= 30
      LOGGER.warn "NAM", "VM#{guestvm[0]} WARNING - EMPTY PCAP FILE!!!! ::.."
      #FileUtils.rm_r(sample_home)
      empty_pcap = true
    end

    dumpvalues = [dump.sha, dump.size, pcaprid, pcapfile, 'false']
    analysis_values = [anal_id, bin.sha, guestvm[0], dump.sha, get_time]

    if pcaprid.nil? || bin.dir_pcap.nil? || bin.sha.nil? || bin.md5.nil?
      LOGGER.error "SANDBOX", "VM#{guestvm[0]} Can't retrieve the required information"
      FileUtils.rm_r(sample_home)
      return false
    end


    LOGGER.debug "DB", "VM#{guestvm[0]} Database insert phase" if VERBOSE

    db = Insertdb.new
    db.begin_t  #needed for rollbacks

    unless empty_pcap
      unless db.insert("traffic_dumps", dumpvalues)
        LOGGER.fatal "DB", "VM#{guestvm[0]} Error while inserting data into table traffic_dumps. Skipping binary #{bin.md5}"
        FileUtils.rm_r(sample_home)
        return false
      end
    end



    unless db.insert("analyses", analysis_values)
      LOGGER.fatal "DB", "VM#{guestvm[0]} Error while inserting data into table analyses. Skipping binary #{bin.md5}"
      FileUtils.rm_r(sample_home)
      return false
    end

    #TODO ADD RT CODE


    #puts "Done, commit changes?"
    #gets
    #puts Insertdb.status

    db.commit
    db.close

    LOGGER.info "MAM", "VM#{guestvm[0]} ".yellow + "Removing file from /bins directory"
    FileUtils.rm(bin.binpath)
    #puts "[MAM]VM#{guestvm[0]} ".yellow + "Releasing virtual machine #{guestvm}"
    LOGGER.info "MAM", "VM#{guestvm[0]} ".yellow + "Process compleated successfully"

  rescue => e

    LOGGER.error "SANDBOX", "VM#{guestvm[0]} An error occurred while analyzing #{bin.filename}, skipping\n"
    LOGGER.error "Dorothy" , "#{$!}\n #{e.inspect} \n #{e.backtrace}" if VERBOSE

    FileUtils.rm_r(sample_home)
    db.rollback unless db.nil?  #rollback in case there is a transaction on going
    return false
  end





end

########################
## VTOTAL SCAN		####
########################
private
def scan(bin)
  #puts "TOTAL", "Forking for VTOTAL"
  @vtotal_threads << Thread.new(bin.sha) {
    LOGGER.info "VTOTAL", "Scanning file #{bin.md5}".yellow

    vt = Vtotal.new
    id = vt.analyze_file(bin.binpath)

    LOGGER.debug "VTOTAL", "Sleeping"

    sleep 15

    until vt.get_report(id)
      LOGGER.info "VTOTAL", "Waiting a while and keep retring..."
      sleep 30
    end

    LOGGER.info("VTOTAL", "#{bin.md5} Detection Rate: #{vt.rate}")
    LOGGER.info("VTOTAL", "#{bin.md5} Family by McAfee: #{vt.family}")

    LOGGER.info "VTOTAL", "Updating DB"
    vtvalues = [bin.sha, vt.family, vt.vendor, vt.version, vt.rate, vt.updated, vt.detected]
    db = Insertdb.new
    db.begin
    begin
      db.insert("malwares", vtvalues)
      db.close
    rescue
      db.rollback
      LOGGER.error "VTOTAL", "Error while inserting values in malware table"
    end

    #TODO upload evidence to RT
  }

end



#########################
##			MAIN	        	#
#########################

def self.start(source=nil, daemon=nil)

  @db = Insertdb.new
  daemon ||= false

  puts "[Dorothy]".yellow +  " Process Started"


  LOGGER.info "Dorothy", "Started".yellow

  if daemon
    check_pid_file PIDFILE
    puts "[Dorothy]".yellow + " Going in backround with pid #{Process.pid}"
    puts "[Dorothy]".yellow + " Logging on #{LOGFILE}"
    Process.daemon
    create_pid_file PIDFILE
    LOGGER.info "Dorothy", "Going in backround with pid #{Process.pid}"
  end

  #Creating a new NAM object for managing the sniffer
  @nam = DorothyNAM.new(DoroSettings.nam)

  @vtotal_threads = []
  @vtotal_threads = []
  @analysis_threads = []

  infinite = true

  #be sure that all the vm are available by forcing their release
  @db.vm_init

  if source # a source has been specified
    while infinite  #infinite loop
      dfm = DorothyFetcher.new(source)
      start_analysis(dfm.bins, daemon)
      infinite = daemon #exit if wasn't set
      wait_end
      LOGGER.info "Dorothy", "SLEEPING" if daemon
      sleep DoroSettings.env[:dtimeout] if daemon # Sleeping a while if -d wasn't set, then quit.
    end
  else  # no sources specified, analyze all of them
    while infinite  #infinite loop
      SOURCES.each do |sname, sinfo|
        selected_source = Hash[SOURCES.select {|k,v| k == sname}]
        dfm = DorothyFetcher.new(selected_source)
        start_analysis(dfm.bins, daemon)
      end
      infinite = daemon #exit if wasn't set
      wait_end
      LOGGER.info "Dorothy", "SLEEPING" if daemon
      sleep DoroSettings.env[:dtimeout] if daemon # Sleeping a while if -d wasn't set, then quit.
    end
  end

  @db.close

end

def wait_end

  unless @vtotal_threads.empty?
    @vtotal_threads.each { |aThread|  aThread.join}
    LOGGER.info "VTOTAL","Process compleated successfully"
  end

  @analysis_threads.each { |aThread|  aThread.join }
  LOGGER.info "Dorothy", "Process finished"

end

def check_pid_file file
  if File.exist? file
    # If we get Errno::ESRCH then process does not exist and
    # we can safely cleanup the pid file.
    pid = File.read(file).to_i
    begin
      Process.kill(0, pid)
    rescue Errno::ESRCH
      stale_pid = true
    rescue
    end

    unless stale_pid
      puts "[Dorothy]".yellow + " Dorothy is already running (pid=#{pid})"
      exit
    end
  end
end

def create_pid_file file
  File.open(file, "w") { |f| f.puts Process.pid }

  # Remove pid file during shutdown
  at_exit do
    Logger.info "Dorothy", "Shutting down." rescue nil
    if File.exist? file
      File.unlink file
    end
  end
end

## Sends SIGTERM to process in pidfile. Server should trap this
# and shutdown cleanly.
def self.stop
  LOGGER.info "Dorothy", "Shutting down."
  pid_file = PIDFILE
  if pid_file and File.exist? pid_file
    pid = Integer(File.read(pid_file))
    Process.kill -15, -pid
    puts "[Dorothy]".yellow + " Process #{pid} terminated"
    LOGGER.info "Dorothy", "Process #{pid} terminated"
  else
    puts "[Dorothy]".yellow +  " Can't find PID file, is Dorothy really running?"
  end
end

end