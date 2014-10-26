#!/bin/env ruby
# encoding: utf-8

# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.

##.for irb debug:
##from $home, irb and :
#load 'dorothy2.rb'; include Dorothy; LOGGER = DoroLogger.new(STDOUT, "weekly"); DoroSettings.load!("#{File.expand_path("~")}/.dorothy.yml")
##/

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
require 'uirusu'
require 'digest'
require 'mail'
require 'io/console'
require 'base64'
require 'open-uri'
require 'csv'
require 'whois'



require File.dirname(__FILE__) + '/dorothy2/do-init'
require File.dirname(__FILE__) + '/dorothy2/Settings'
require File.dirname(__FILE__) + '/dorothy2/deep_symbolize'
require File.dirname(__FILE__) + '/dorothy2/vtotal'
require File.dirname(__FILE__) + '/dorothy2/VSM'
require File.dirname(__FILE__) + '/dorothy2/NAM'
require File.dirname(__FILE__) + '/dorothy2/BFM'
require File.dirname(__FILE__) + '/dorothy2/do-utils'
require File.dirname(__FILE__) + '/dorothy2/do-logger'
require File.dirname(__FILE__) + '/dorothy2/version'





module Dorothy

  def start_analysis(queue)
    #Create a mutex for monitoring the access to the methods
    @queue_size = queue.size

     unless @queue_size == 0
      queue.each do |qentry|

        bin = Loadmalw.new(qentry["path"].strip, qentry["filename"])
        profile = Util.load_profile(qentry['profile'])

        next unless profile
        next unless check_support(bin, qentry["id"], profile)
        scan(bin) if profile[1]['vtotal_query']   #avoid to stress VT if we are just testing

        if MANUAL #no multithread
          execute_analysis(bin, qentry["id"], profile)
        else      #Use multithreading
          @analysis_threads << Thread.new(bin.filename){
            sleep rand(@queue_size * 2)  #OPTIMIZE #REVIEW
            execute_analysis(bin, qentry["id"],profile,rand(30))
          }
        end
      end
    else
      LOGGER.warn("Analyser", "The queue is currently empty!") if DEBUG
    end
  end



  def execute_analysis(bin, qentry, profile, timer=0)
    db = Insertdb.new

    prof_info = profile[1]

    #guestvm struct: array ["sandbox id", "sandbox name", "ipaddress", "user", "password"]
    sleep timer until (guestvm = db.find_vm(prof_info['OS']['type'], prof_info['OS']['version'], prof_info['OS']['lang']))

    db.analysis_queue_mark(qentry, "processing")

    begin
      if analyze(bin, guestvm, qentry, profile)
        db.analysis_queue_mark(qentry, "analysed")
      else
        db.analysis_queue_mark(qentry, "error")
      end
    rescue
      db.analysis_queue_mark(qentry, "cancelled")
    end

    db.free_vm(guestvm[0])
    db.close

  end




###ANALYZE THE SOURCE
  def analyze(bin, guestvm, queueid, profile)

    #RESERVING AN ANALYSIS ID
    db = Insertdb.new
    anal_id = db.get_anal_id
    prof_info = profile[1]

    #set home vars
    sample_home = DoroSettings.env[:analysis_dir] + "/#{anal_id}"
    bin.dir_bin = "#{sample_home}/bin/"
    bin.dir_pcap = "#{sample_home}/pcap/"
    bin.dir_screens = "#{sample_home}/screens/"
    bin.dir_downloads = "#{sample_home}/downloads/"

    vm_log_header = "VM#{guestvm[0]} ".yellow + "[" + "#{anal_id}".red + "] "


    LOGGER.info "VSM", vm_log_header + "Analyzing binary #{bin.filename}"

    begin
      #crate dir structure in analisys home
      unless File.directory?(sample_home)
        LOGGER.info "VSM",vm_log_header + "Creating DIRS"
        Dir.mkdir sample_home
        Dir.mkdir bin.dir_bin
        Dir.mkdir bin.dir_pcap
        Dir.mkdir bin.dir_screens
        Dir.mkdir bin.dir_downloads

        LOGGER.debug "VSM", sample_home
        LOGGER.debug "VSM",bin.dir_bin
        LOGGER.debug "VSM",bin.dir_pcap
        LOGGER.debug "VSM",bin.dir_screens


      else
        LOGGER.warn "VSM",vm_log_header + "Malware #{bin.md5} sample_home already present, WTF!? Skipping.."
        #print "\n"
        return false
      end


      FileUtils.ln_s(bin.binpath,bin.dir_bin + bin.filename)  # put a symbolic link from the analysis folder to the bins repo


      #Creating a new VSM object for managing the SandBox VM
      LOGGER.info "VSM",vm_log_header + "Connecting to ESX Server #{DoroSettings.esx[:host]}"

      vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4])
      reverted = false


      #Copy File to VM
      r = 0

      begin
        vsm.check_internet
      rescue
        if r <= 2
          r = r+1
          LOGGER.warn "VSM",vm_log_header + " GUESTOS Connection problem to Internet, retry n. #{r}/3"
          sleep 20
          retry
        end
        LOGGER.error "VSM", vm_log_header + " Guest system is not able to connect to internet"
        r = 0
        retry
      end



      LOGGER.info "VSM",vm_log_header + "Copying #{bin.md5} to VM"

      filecontent = File.open(bin.binpath, "rb") { |byte| byte.read } #load filebinary
      vsm.copy_file(bin.full_filename,filecontent)    #Using full_filename, we do want to be sure that it has an extension

      #Start Sniffer
      dumpname = anal_id.to_s + "-" + bin.md5
      pid = @nam.start_sniffer(guestvm[2],DoroSettings.nam[:interface], dumpname, DoroSettings.nam[:pcaphome])
      LOGGER.info "NAM",vm_log_header + "Start sniffing module"
      LOGGER.debug "NAM",vm_log_header + "Tcpdump instance #{pid} started"

      #sleep 5

      @screenshots = Array.new

      #Execute File into VM
      LOGGER.info "VSM",vm_log_header + "Executing #{bin.full_filename} with #{prof_info['extensions'][bin.extension]['prog_name']}"

      if MANUAL
        LOGGER.debug "MANUAL-MODE",vm_log_header + " MANUAL mode detected. You can now logon to rdp://#{guestvm[2]} "

        menu="
        #{"Choose your next action:".yellow}
          ------------------------
          #{"1".yellow}) Take Screenshot
          #{"2".yellow}) Take ProcessList
          #{"3".yellow}) Execute #{bin.full_filename}
        #{"0".yellow}) Continue and revert the machine.
          ------------------------

          Select a nuber:"

        print menu
        $stdout.flush
        answer = gets.chop

        until answer == "0"
          case answer
            when "1" then
              @screenshots.push vsm.screenshot
              LOGGER.info "MANUAL-MODE",vm_log_header +  "Screenshot taken"
            when "2"
              @current_procs = vsm.get_running_procs
              LOGGER.info "MANUAL-MODE",vm_log_header +  "Current ProcessList taken"
              @current_procs.each_key do |pid|
                LOGGER.info "MANUAL-MODE", vm_log_header + "[" + "+".red + "]" + " PID: #{pid}, NAME: #{@current_procs[pid]["pname"]}, COMMAND: #{@current_procs[pid]["cmdLine"]}"
              end
            when "3"
              guestpid = vsm.exec_file("C:\\#{bin.full_filename}",prof_info['extensions'][bin.extension])
              LOGGER.debug "MANUAL-MODE",vm_log_header + "Program executed with PID #{guestpid}"
            #when "x" then -- More interactive actions to add
            else
              print menu
              $stdout.flush
          end
          answer = gets.chop
        end

        LOGGER.info "MANUAL-MODE",vm_log_header + "Moving forward.."


      else
        guestpid = vsm.exec_file("C:\\#{bin.full_filename}",prof_info['extensions'][bin.extension])
        LOGGER.debug "VSM",vm_log_header + "Program executed with PID #{guestpid}"
        sleep 1
        returncode = vsm.get_status(guestpid)
        raise "The program was not correctly executed into the Sandbox. Status code: #{returncode}" unless returncode == 0 || returncode.nil?

        LOGGER.info "VSM",vm_log_header + " Sleeping #{prof_info['sleeptime']} seconds".yellow
        sleep prof_info['screenshots']['delay_first'] % prof_info['sleeptime']

        prof_info['screenshots']['number'].times do
          @screenshots.push vsm.screenshot
          sleep prof_info['screenshots']['delay_inbetween'] % prof_info['sleeptime'] if prof_info['screenshots']['delay_inbetween']
        end

        sleep prof_info['sleeptime']

        #Get Procs
        @current_procs = vsm.get_running_procs

      end


      #Stop Sniffer, revert the VM
      stop_nam_revertvm(@nam, pid, vsm, reverted, vm_log_header)

      vsm.revert_vm
      reverted = true

      #Analyze new procs
      LOGGER.info "VSM", vm_log_header + "Checking for spowned processes"

      unless @current_procs.nil?
        @procs = vsm.get_new_procs(@current_procs, "#{DoroSettings.env[:home]}/etc/#{profile[0]}_baseline_procs.yml")
        if @procs.size > 0
          LOGGER.info "VSM", vm_log_header + "#{@procs.size} new process(es) found"
          @procs.each_key do |pid|
            LOGGER.info "VSM", vm_log_header + "[" + "+".red + "]" + " PID: #{pid}, NAME: #{@procs[pid]["pname"]}, COMMAND: #{@procs[pid]["cmdLine"]}"
          end
        end
      end

      #Downloading PCAP
      LOGGER.info "NAM", vm_log_header + "Downloading #{dumpname}.pcap to #{bin.dir_pcap}"
      Ssh.download(DoroSettings.nam[:host], DoroSettings.nam[:user],DoroSettings.nam[:pass], DoroSettings.nam[:pcaphome] + "/#{dumpname}.pcap", bin.dir_pcap)

      #Downloading Screenshots from esx
      LOGGER.info "NAM", vm_log_header + "Downloading Screenshots"

      @screenshots.each do |screen|
        Ssh.download(DoroSettings.esx[:host],DoroSettings.esx[:user], DoroSettings.esx[:pass], screen, bin.dir_screens)
        #Put them to 644
        File.chmod(0644, bin.dir_screens + File.basename(screen), bin.dir_screens + File.basename(screen) )
      end

      #UPDATE DOROTHIVE DB###################################

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

      LOGGER.debug "NAM", vm_log_header + "Pcaprid: " + pcaprid

      empty_pcap = false

      if dump.size <= 30
        LOGGER.warn "NAM", vm_log_header + "WARNING - EMPTY PCAP FILE!!!! ::.."
        #FileUtils.rm_r(sample_home)
        empty_pcap = true
      end

      dumpvalues = [dump.sha, dump.size, pcaprid, dump.binpath, 'false']
      dump.sha = "EMPTYPCAP" if empty_pcap
      analysis_values = [anal_id, bin.sha, guestvm[0], dump.sha, Util.get_time, queueid]

      if pcaprid.nil? || bin.dir_pcap.nil? || bin.sha.nil? || bin.md5.nil?
        LOGGER.error "VSM", "VM#{guestvm[0]} Can't retrieve the required information"
        raise "Some info missing.."
      end


      LOGGER.debug "DB", "VM#{guestvm[0]} Database insert phase"

      db.begin_t  #needed for rollbacks
      in_transaction = true

      unless empty_pcap
        unless db.insert("traffic_dumps", dumpvalues)
          LOGGER.fatal "DB", "VM#{guestvm[0]} Error while inserting data into table traffic_dumps. Skipping binary #{bin.md5}"
          raise "DB-ERROR"
        end
      end



      unless db.insert("analyses", analysis_values)
        LOGGER.fatal "DB", vm_log_header + "Error while inserting data into table analyses. Skipping binary #{bin.md5}"
        raise "DB-ERROR"
      end

      @procs.each_key do |pid|
        @procs[pid]["endTime"] ? end_time = Util.get_time(@procs[pid]["endTime"]) : end_time = "null"
        @procs[pid]["exitCode"] ? exit_code = @procs[pid]["exitCode"] : exit_code = "null"
        sys_procs_values = [anal_id, pid, @procs[pid]["pname"], @procs[pid]["owner"], @procs[pid]["cmdLine"], Util.get_time(@procs[pid]["startTime"]), end_time, exit_code ]
        unless db.insert("sys_procs", sys_procs_values)
          LOGGER.fatal "DB", vm_log_header + "Error while inserting data into table sys_procs. Skipping binary #{bin.md5}"
          raise "DB-ERROR"
        end
      end


      #TODO ADD RT CODE


      db.commit
      in_transaction = false
      db.close

      LOGGER.info "VSM", vm_log_header + "Process compleated successfully"

    rescue SignalException #, RuntimeError
      LOGGER.warn "DOROTHY", "SIGINT".red + " Catched, exiting gracefully."
      stop_nam_revertvm(@nam, pid, vsm, reverted, vm_log_header)
      LOGGER.debug "VSM", vm_log_header + "Removing working dir"
      FileUtils.rm_r(sample_home)

      if in_transaction
        db.rollback  #rollback in case there is a transaction on going
        db.close
      end

      raise
    rescue Exception => e
      LOGGER.error "VSM", vm_log_header + "An error occurred while analyzing #{bin.filename}, skipping\n"
      LOGGER.debug "Analyser" , "#{$!}\n #{e.inspect} \n #{e.backtrace}"

      LOGGER.warn "Analyser", vm_log_header + "Stopping NAM instances if presents, reverting the Sandbox, and removing working directory"

      stop_nam_revertvm(@nam, pid, vsm, reverted, vm_log_header)
      LOGGER.debug "VSM", vm_log_header + "Removing working dir"
      FileUtils.rm_r(sample_home)

      if in_transaction
        db.rollback  #rollback in case there is a transaction on going
        db.close
      end

      LOGGER.warn "VSM", vm_log_header + "Recover finished."
      false

    end

  end



  #########################
  ##			MAIN	        	#
  #########################

  def self.start(daemon=false)
    @vtotal_threads = []
    @analysis_threads = []
    @bins = []
    @db = Insertdb.new


    LOGGER.info "Analyser", "Started".yellow


    #Creating a new NAM object for managing the sniffer
    @nam = Doro_NAM.new(DoroSettings.nam)
    #Be sure that there are no open tcpdump instances opened
    @nam.init_sniffer


    finish = false
    infinite = true

    #be sure that all the vm are available by forcing their release
    @db.vm_init

    #Check if the are some analysis pending in the queue
    unless @db.analysis_queue_pull.empty? || daemon
      LOGGER.warn "WARNING", "There are some pending analyses in the queue, what do you want to do?"
      menu="
          --------------------------------------
          #{"1".yellow}) Mark as analysed and continue
          #{"2".yellow}) Append the new files and analyse also the pending ones
          #{"3".yellow}) List pending analyses
          --------------------------------------
          Select a nuber:"

      print menu
      $stdout.flush
      answer = gets.chop

      until finish
        case answer
          when "1" then
            @db.analysis_queue_mark_all
            LOGGER.info "Analyser", "Queue Cleared, proceding.."
            finish = true

          when "2"
            LOGGER.info "Analyser", "Proceding.."
            finish = true

          when "3"
            @db.analysis_queue_view

          else
            LOGGER.warn "Analyser", "There are some pending analyses in the queue, what do you want to do?"
            print menu
            $stdout.flush
        end

        answer = gets.chop unless finish
      end
    end


    begin
      while infinite  #infinite loop

        begin
          start_analysis(@db.analysis_queue_pull)
          infinite = daemon #exit if wasn't set
        rescue SignalException #, RuntimeError
          LOGGER.warn "DOROTHY", "SIGINT".red + " Catched [2], exiting gracefully."
          stop_running_analyses
          Process.kill('HUP',Process.pid)
        end

        # Sleeping a while if -d wasn't set, then quit.
        if daemon
          LOGGER.info "Analyser", "SLEEPING" if DEBUG
          sleep DoroSettings.env[:sleeptime].to_i
        end

        wait_end  #TODO: is really required (here)?

      end
    rescue SignalException #, RuntimeError
      LOGGER.warn "DOROTHY", "SIGINT".red + " Catched [3], exiting gracefully."
    end
    @db.close

  end

  def wait_end

    unless @vtotal_threads.empty?
      @vtotal_threads.each { |aThread|  aThread.join}
      LOGGER.info "VTOTAL","Process compleated successfully" if DEBUG
    end

    @analysis_threads.each { |aThread|  aThread.join }
    LOGGER.info "Analyser", "Process finished" if DEBUG

  end

  ############# END OF MAIN








  #Stop NAM instance and Revert VM
  def stop_nam_revertvm(nam, pid, vsm, reverted, vm_log_header)

    if pid
      LOGGER.info "VSM", vm_log_header + " Stopping sniffing module " + pid.to_s
      nam.stop_sniffer(pid)
    end

    unless reverted || vsm.nil?
      LOGGER.info "VSM", vm_log_header + " Reverting VM"
      vsm.revert_vm
      sleep 3   #wait some seconds for letting the vm revert..
    end
  end


 #Check the sample's md5 hash with VirusTotal
 def scan(bin)
    #puts "TOTAL", "Forking for VTOTAL"
    @vtotal_threads << Thread.new(bin.sha) {
      LOGGER.info "VTOTAL", "Scanning file #{bin.md5}".yellow

      vt_results = Vtotal.check_hash(bin.md5)

      if vt_results != false

        LOGGER.info "VTOTAL", vt_results[:rate]
        db = Insertdb.new
        db.begin_t

        begin
          @id = db.get_curr_malwares_id
          vtvalues = [bin.sha, vt_results[:rate], vt_results[:positive], vt_results[:date], vt_results[:link], @id]
          db.insert("malwares", vtvalues)

          #Instert DB
          vt_results[:results].each do |av|
            vendor = av[0]
            if av[1]["detected"]
              family = av[1]["result"]
              updated = (av[1]["update"] != "-" ? av[1]["update"] : "null")
              version = (av[1]["version"] != "-" ? av[1]["version"] : "null")
              vtvalues = [@id, vendor, family, version, updated]
              db.insert("av_signs", vtvalues)
            end
          end

        rescue => e
          LOGGER.debug "VTOTAL" , "#{$!}\n #{e.inspect} \n #{e.backtrace}"
          db.rollback
        end
        db.commit
        db.close
      end
    }
  end


  ###Create Baseline
  def self.run_baseline(profile)
    db = Insertdb.new
    db.vm_init
    prof_info = profile[1]
    guestvm = db.find_vm(prof_info['OS']['type'], prof_info['OS']['version'], prof_info['OS']['lang'])
    if guestvm
      begin
        LOGGER.info "VSM","VM#{guestvm[0]}".red + " Executng the baseline run"
        vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4])
        LOGGER.info "VSM","VM#{guestvm[0]}".red + " Sleeping #{prof_info['sleeptime']} seconds".yellow
        sleep prof_info['sleeptime']
        vsm.get_running_procs(nil, true, "#{DoroSettings.env[:home]}/etc/#{profile[0]}_baseline_procs.yml")  #save on file
        LOGGER.info "VSM", "VM#{guestvm[0]} ".red + "Reverting VM".yellow
        vsm.revert_vm
        db.free_vm(guestvm[0])
        db.close
      rescue => e
        LOGGER.error "VSM", "VM#{guestvm[0]} ".yellow + "An error occurred while performing the BASELINE run, please retry"
        LOGGER.debug "Analyser" , "VM#{guestvm[0]} ".yellow + "#{$!}\n #{e.inspect} \n #{e.backtrace}"
        LOGGER.warn "VSM", "VM#{guestvm[0]} ".yellow + "[RECOVER] Reverting VM"
        vsm.revert_vm   #TODO vsm var might be nil here
        db.free_vm(guestvm[0])
        db.close
      end
    else
      LOGGER.fatal "VSM", "[CRITICAL]".red + " There are no free VM at the moment..how it is possible?"
    end
  end


  #Check if the sample extension is supported (= is configured into the extension.yml).
  def check_support(bin, qentry, profile)
    if profile[1]['extensions'].key?(bin.extension)
      true
    else
      db = Insertdb.new           #TODO too many db sessions opened. review, and try to use less
      db.analysis_queue_mark(qentry, "error")
      db.close
      LOGGER.warn("VSM", "File extension #{bin.extension} currently not configured in the selected profile #{profile[0]}, skipping")
      LOGGER.debug("VSM", "Filtype: #{bin.type}")
      false
    end
  end



  def self.stop_running_analyses
    LOGGER.info "Analyser", "Killing curent live analysis threads.."
    @analysis_threads.each { |aThread|
      aThread.raise
      aThread.join
    }
  end

end