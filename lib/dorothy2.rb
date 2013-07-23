# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.

##for irb debug:
##from $home, irb and :
##load 'lib/dorothy2.rb'; include Dorothy; LOGGER = DoroLogger.new(STDOUT, "weekly"); DoroSettings.load!('etc/dorothy.yml'); VERBOSE = true

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
require 'ftools' #deprecated in ruby 1.9 !!!
require 'filemagic'
require 'md5'

require File.dirname(__FILE__) + '/dorothy2/do-init'
require File.dirname(__FILE__) + '/dorothy2/Settings'
require File.dirname(__FILE__) + '/dorothy2/deep_symbolize'
require File.dirname(__FILE__) + '/dorothy2/environment'
require File.dirname(__FILE__) + '/dorothy2/vtotal'
require File.dirname(__FILE__) + '/dorothy2/VSM'
require File.dirname(__FILE__) + '/dorothy2/NAM'
require File.dirname(__FILE__) + '/dorothy2/BFM'
require File.dirname(__FILE__) + '/dorothy2/do-utils'
require File.dirname(__FILE__) + '/dorothy2/do-logger'

module Dorothy

  def get_time
    time = Time.new
    time.utc.strftime("%Y-%m-%d %H:%M:%S")
  end


  def start_analysis(bins)
    @binum = bins.size
    bins.each do |bin|
      next unless check_support(bin)
      scan(bin) unless DoroSettings.env[:testmode]   #avoid to stress VT if we are just testing
      if MANUAL #no multithread
        db = Insertdb.new
        guestvm = db.find_vm
        analyze(bin, guestvm)
        db.free_vm(guestvm[0])
        db.close
      else      #Use multithreading
        @analysis_threads << Thread.new(bin.filename){
          db = Insertdb.new
          sleep rand(@binum * 2)  #OPTIMIZE #REVIEW
          sleep rand(30) while !(guestvm = db.find_vm)  #guestvm struct: array ["sandbox id", "sandbox name", "ipaddress", "user", "password"]
          analyze(bin, guestvm)
          db.free_vm(guestvm[0])
          db.close
        }
      end
    end
  end


  def check_support(bin)
    if EXTENSIONS.key?(bin.extension)
      true
    else
      LOGGER.warn("SANDBOX", "File extension #{bin.extension} currently not configured in etc/extensions.yml, skipping")
      LOGGER.debug("SANDBOX", "Filtype: #{bin.type}") if VERBOSE
      dir_not_supported = File.dirname(bin.binpath) + "/not_supported"
      Dir.mkdir(dir_not_supported) unless File.exists?(dir_not_supported)
      FileUtils.cp(bin.binpath,dir_not_supported) #mv?
      FileUtils.rm(bin.binpath) ## mv?
      return false
    end
  end

###ANALYZE THE SOURCE
  def analyze(bin, guestvm)

    #RESERVING AN ANALYSIS ID
    db = Insertdb.new
    anal_id = db.get_anal_id
    reverted = false

    #set home vars
    sample_home = DoroSettings.env[:analysis_dir] + "/#{anal_id}"
    bin.dir_bin = "#{sample_home}/bin/"
    bin.dir_pcap = "#{sample_home}/pcap/"
    bin.dir_screens = "#{sample_home}/screens/"
    bin.dir_downloads = "#{sample_home}/downloads/"


    LOGGER.info "SANDBOX", "VM#{guestvm[0]} ".yellow + "[" + "#{anal_id}".red + "]" + " Analyzing binary #{bin.filename}"

    begin
      #crate dir structure in analisys home
      unless File.directory?(sample_home)
        LOGGER.info "VSM","VM#{guestvm[0]} ".yellow + "Creating DIRS"
        Dir.mkdir sample_home
        Dir.mkdir bin.dir_bin
        Dir.mkdir bin.dir_pcap
        Dir.mkdir bin.dir_screens
        Dir.mkdir bin.dir_downloads

        if VERBOSE
          LOGGER.debug "VSM", sample_home
          LOGGER.debug "VSM",bin.dir_bin
          LOGGER.debug "VSM",bin.dir_pcap
          LOGGER.debug "VSM",bin.dir_screens
        end

      else
        LOGGER.warn "SANDBOX","Malware #{bin.md5} sample_home already present, WTF!? Skipping.."
        #print "\n"
        return false
      end



      FileUtils.cp(bin.binpath,bin.dir_bin)  # mv?


      #Creating a new VSM object for managing the SandBox VM
      LOGGER.info "VSM","VM#{guestvm[0]} ".yellow + "Connecting to ESX Server #{DoroSettings.esx[:host]}"

      vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4])

      #Copy File to VM
      r = 0

      begin
        vsm.check_internet
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



      LOGGER.info "VSM","VM#{guestvm[0]} ".yellow + "Copying #{bin.md5} to VM"

      filecontent = File.open(bin.binpath, "rb") { |byte| byte.read } #load filebinary
      vsm.copy_file(bin.filename,filecontent)

      #Start Sniffer
      dumpname = anal_id.to_s + "-" + bin.md5
      pid = @nam.start_sniffer(guestvm[2],DoroSettings.nam[:interface], dumpname, DoroSettings.nam[:pcaphome])
      LOGGER.info "NAM","VM#{guestvm[0]} ".yellow + "Start sniffing module"
      LOGGER.debug "NAM","VM#{guestvm[0]} ".yellow + "Tcpdump instance #{pid} started" if VERBOSE

      sleep 5

      @screenshots = Array.new

      #Execute File into VM
      LOGGER.info "VSM","VM#{guestvm[0]} ".yellow + "Executing #{bin.md5} File into VM"

      if MANUAL
        LOGGER.debug "VSM","VM#{guestvm[0]} ".yellow + " MANUAL mode detected. You can now logon to rdp:// "

        LOGGER.info "MANUAL-MODE","VM#{guestvm[0]} ".yellow + "

          Choose your next action:
          1) Take Screenshot
          2) Take ProcessList
          3) Execute #{bin.filename}
          0) Continue and revert the machine.

          Select a nuber:"
        answer = gets.chop

        until answer == "0"
          case answer
            when "1" then
              @screenshots.push vsm.screenshot
              LOGGER.info "MANUAL-MODE","VM#{guestvm[0]} ".yellow +  "Screenshot taken"
            when "2"
              @current_procs = vsm.get_running_procs
              LOGGER.info "MANUAL-MODE","VM#{guestvm[0]} ".yellow +  "Current ProcessList taken"
            when "3"
              guestpid = vsm.exec_file("C:\\#{bin.filename}",EXTENSIONS[bin.extension])
              LOGGER.debug "MANUAL-MODE","VM#{guestvm[0]} ".yellow + "Program executed with PID #{guestpid}"
            #when "x" then -- More interactive actions to add
            else
              LOGGER.info "MANUAL-MODE","VM#{guestvm[0]} ".yellow +  "Please select a number"
          end
          answer = gets.chop
        end

        LOGGER.info "MANUAL-MODE","VM#{guestvm[0]} ".yellow + "Moving forward.."


      else
        guestpid = vsm.exec_file("C:\\#{bin.filename}",EXTENSIONS[bin.extension])
        LOGGER.debug "VSM","VM#{guestvm[0]} ".yellow + "Program executed with PID #{guestpid}" if VERBOSE
        sleep 1
        returncode = vsm.get_status(guestpid)
        raise "The program was not correctly executed into the Sandbox. Status code: #{returncode}" unless returncode == 0 || returncode.nil?

        LOGGER.info "VSM","VM#{guestvm[0]}".yellow + " Sleeping #{DoroSettings.sandbox[:sleeptime]} seconds".yellow
        sleep DoroSettings.sandbox[:screen1time] % DoroSettings.sandbox[:sleeptime]

        DoroSettings.sandbox[:num_screenshots].times do
          @screenshots.push vsm.screenshot
          sleep DoroSettings.sandbox[:screen2time] % DoroSettings.sandbox[:sleeptime]
        end

        sleep DoroSettings.sandbox[:sleeptime]

        #Get Procs
        @current_procs = vsm.get_running_procs

      end


      #Stopt Sniffer, revert the VM
      stop_nam_revertvm(@nam, pid, vsm, guestvm[0], reverted, db)

      vsm.revert_vm
      reverted = true

      #Analyze new procs
      LOGGER.info "VSM", "VM#{guestvm[0]} ".yellow + "Checking for spowned processes"

      unless @current_procs.nil?
        procs = vsm.get_new_procs(@current_procs)
        if procs.size > 0
          LOGGER.info "VSM", "#{procs.size} new process(es) found"
          procs.each_key do |pid|
            LOGGER.info "VSM", "[" + "+".red + "]" + " PID: #{pid}, NAME: #{procs[pid]["pname"]}, COMMAND: #{procs[pid]["cmdLine"]}"
          end
        end
      end

      #Downloading PCAP
      LOGGER.info "NAM", "VM#{guestvm[0]} ".yellow + "Downloading #{dumpname}.pcap to #{bin.dir_pcap}"
      Ssh.download(DoroSettings.nam[:host], DoroSettings.nam[:user],DoroSettings.nam[:pass], DoroSettings.nam[:pcaphome] + "/#{dumpname}.pcap", bin.dir_pcap)

      #Downloading Screenshots from esx
      LOGGER.info "NAM", "VM#{guestvm[0]} ".yellow + "Downloading Screenshots"

      @screenshots.each do |screen|
        Ssh.download(DoroSettings.esx[:host],DoroSettings.esx[:user], DoroSettings.esx[:pass], screen, bin.dir_screens)
        #Put them to 644
        File.chmod(0644, bin.dir_screens + File.basename(screen), bin.dir_screens + File.basename(screen) )
      end





      #####################
      #UPDATE DOROTHIBE DB#
      #####################

      dump = Loadmalw.new(bin.dir_pcap + dumpname + ".pcap")

      #TODO: dump.filname depends on the PCAPR pcaps path.
      #9/pcap/9-7bbf2e721d9b03988dc448344fd45a0c.pcap
      #pcapr_filename = anal_id + "/pcap/" + dump.filename


      if DoroSettings.pcapr[:local]
        pcapr_filename = "#{anal_id}/pcap/#{dump.filename}"
        pcaprid = Loadmalw.calc_pcaprid(pcapr_filename, dump.size).rstrip
      else
        pcaprid = Loadmalw.calc_pcaprid(dump.filename, dump.size).rstrip
      end

      LOGGER.debug "NAM", "VM#{guestvm[0]} ".yellow + "Pcaprid: " + pcaprid if VERBOSE

      empty_pcap = false

      if dump.size <= 30
        LOGGER.warn "NAM", "VM#{guestvm[0]} WARNING - EMPTY PCAP FILE!!!! ::.."
        #FileUtils.rm_r(sample_home)
        empty_pcap = true
      end

      dumpvalues = [dump.sha, dump.size, pcaprid, dump.binpath, 'false']
      dump.sha = "EMPTYPCAP" if empty_pcap
      analysis_values = [anal_id, bin.sha, guestvm[0], dump.sha, get_time]

      if pcaprid.nil? || bin.dir_pcap.nil? || bin.sha.nil? || bin.md5.nil?
        LOGGER.error "SANDBOX", "VM#{guestvm[0]} Can't retrieve the required information"
        FileUtils.rm_r(sample_home)
        return false
      end


      LOGGER.debug "DB", "VM#{guestvm[0]} Database insert phase" if VERBOSE

      db.begin_t  #needed for rollbacks
      in_transaction = true

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

      db.commit
      in_transaction = false
      db.close

      LOGGER.info "VSM", "VM#{guestvm[0]} ".yellow + "Removing file from /bins directory"
      FileUtils.rm(bin.binpath)
      LOGGER.info "VSM", "VM#{guestvm[0]} ".yellow + "Process compleated successfully"

    rescue SignalException
      LOGGER.warn "DOROTHY", "SIGINT".red + " Catched, exiting gracefully."
      stop_nam_revertvm(@nam, pid, vsm, guestvm[0], reverted, db, in_transaction)
      LOGGER.debug "SANDBOX", "VM#{guestvm[0]} ".red + "Removing working dir"
      FileUtils.rm_r(sample_home)
      if in_transaction
        db.rollback  #rollback in case there is a transaction on going
        db.close
      end

    rescue Exception => e
      LOGGER.error "SANDBOX", "VM#{guestvm[0]} An error occurred while analyzing #{bin.filename}, skipping\n"
      LOGGER.debug "Dorothy" , "#{$!}\n #{e.inspect} \n #{e.backtrace}" if VERBOSE

      LOGGER.warn "DOROTHY", "Stopping NAM instances if presents, reverting the Sandbox, and removing working directory"

      stop_nam_revertvm(@nam, pid, vsm, guestvm[0], reverted, db, in_transaction)
      LOGGER.debug "SANDBOX", "VM#{guestvm[0]} ".red + "Removing working dir"

      FileUtils.rm_r(sample_home)

      if in_transaction
        db.rollback  #rollback in case there is a transaction on going
        db.close
      end

      LOGGER.warn "SANDBOX", "VM#{guestvm[0]} ".red + "Recovering finished."


    end

  end

#Stop NAM instance and Revert VM
def stop_nam_revertvm(nam, pid, vsm, guestvm, reverted, db, in_transaction=false)

  if pid
    LOGGER.info "VSM", "VM#{guestvm}".yellow + " Stopping sniffing module " + pid.to_s
    nam.stop_sniffer(pid)
  end

  unless reverted
    LOGGER.info "VSM", "VM#{guestvm}".yellow + " Reverting VM"
    vsm.revert_vm
    sleep 5
  end
end

###Create Baseline
  def run_baseline
    db = Insertdb.new
    guestvm = db.find_vm
    LOGGER.info "VSM","VM#{guestvm[0]}".red + " Executng the baseline run"
    vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4])
    vsm.check_internet
    LOGGER.info "VSM","VM#{guestvm[0]}".red + " Sleeping #{DoroSettings.sandbox[:sleeptime]} seconds".yellow
    sleep DoroSettings.sandbox[:sleeptime]
    vsm.get_running_procs(nil, true)  #save on file
    LOGGER.info "SANDBOX", "VM#{guestvm[0]} ".red + "Reverting VM".yellow
    vsm.revert_vm
    db.free_vm(guestvm[0])
    db.close
  rescue => e
    LOGGER.error "VSM", "VM#{guestvm[0]} An error occurred while performing the BASELINE run, please retry"
    LOGGER.debug "Dorothy" , "#{$!}\n #{e.inspect} \n #{e.backtrace}" if VERBOSE
    LOGGER.warn "SANDBOX", "VM#{guestvm[0]} ".red + "[RECOVER] Reverting VM".yellow
    vsm.revert_vm
    db.free_vm(guestvm[0])
    db.close
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

      LOGGER.info "VTOTAL", "#{bin.md5} Detection Rate: #{vt.rate}"
      LOGGER.info "VTOTAL", "#{bin.md5} Family by McAfee: #{vt.family}"

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
      check_pid_file DoroSettings.env[:pidfile]
      puts "[Dorothy]".yellow + " Going in backround with pid #{Process.pid}"
      puts "[Dorothy]".yellow + " Logging on #{DoroSettings.env[:logfile]}"
      Process.daemon
      create_pid_file DoroSettings.env[:pidfile]
      puts "[Dorothy]".yellow +  " Going in backround with pid #{Process.pid}"
    end

    #Creating a new NAM object for managing the sniffer
    @nam = Doro_NAM.new(DoroSettings.nam)

    @vtotal_threads = []
    @vtotal_threads = []
    @analysis_threads = []

    infinite = true

    #be sure that all the vm are available by forcing their release
    @db.vm_init

    if source # a source has been specified
      while infinite  #infinite loop
        dfm = DorothyFetcher.new(source)
        start_analysis(dfm.bins)
        infinite = daemon #exit if wasn't set
        wait_end
        LOGGER.info "Dorothy", "SLEEPING" if daemon
        sleep DoroSettings.env[:dtimeout] if daemon # Sleeping a while if -d wasn't set, then quit.
      end
    else  # no sources specified, analyze all of them
      while infinite  #infinite loop
        sources = YAML.load_file(DoroSettings.env[:home] + '/etc/sources.yml')
        sources.keys.each do |sname|
          dfm = DorothyFetcher.new(sources[sname])
          start_analysis(dfm.bins)
        end
        infinite = daemon #exit if wasn't set
        wait_end
        LOGGER.info "Dorothy", "SLEEPING" if daemon
        sleep DoroSettings.env[:dtimeout].to_i if daemon # Sleeping a while if -d wasn't set, then quit.
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

  def check_pid_file(file)
    if File.exist? file
      # If we get Errno::ESRCH then process does not exist and
      # we can safely cleanup the pid file.
      pid = File.read(file).to_i
      begin
        Process.kill(0, pid)
      rescue Errno::ESRCH
        stale_pid = true
      end

      unless stale_pid
        puts "[Dorothy]".yellow + " Dorothy is already running (pid=#{pid})"
        exit(1)
      end
    end
  end

  def create_pid_file(file)
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
    pid_file = DoroSettings.env[:pidfile]
    if pid_file and File.exist? pid_file
      pid = Integer(File.read(pid_file))
      Process.kill(-15, -pid)
      LOGGER.info "Dorothy", "Process #{pid} terminated"
    else
      LOGGER.info "Dorothy", "Can't find PID file, is Dorothy really running?"
    end
  end

end