#!/bin/env ruby
# encoding: utf-8

# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.

module Dorothy

  module Util
    extend self

    def write(file, string)
      File.open(file , 'w') {|f| f.write(string) }
    end

    def get_time(local=Time.new)
      time = local
      case local.class.to_s
        when 'Time'
          time.utc.strftime("%Y-%m-%d %H:%M:%S")
        when 'DateTime'
          time.strftime("%Y-%m-%d %H:%M:%S")
        else
          time
      end
    end

    def exists?(file)
      File.exist?(file)
    end


    def load_profile(p_name)
      p = YAML.load_file(DoroSettings.env[:home] + '/etc/profiles.yml').select {|k| k == p_name}.first

      if p.nil?
        LOGGER.warn "PROFILE", "Warning, the profile specified (#{p_name}) doesn't exist in profiles.yml. Skipping"
        false
      else
        p
      end

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
          puts "[" + "+".red + "] " +  "[Dorothy]".yellow + " Dorothy is already running (pid=#{pid})"
          false
        end
        true
      end
    end

    def create_pid_file(file, pid)
      File.open(file, "w") { |f| f.puts pid }

      ## Sends SIGTERM to process in pidfile. Server should trap this
      # and shutdown cleanly.
      at_exit do
        if File.exist? file
          File.unlink file
        end
      end
    end

    def stop_process(doro_module)

      pid_file = DoroSettings.env[:pidfiles] + '/' + doro_module + '.pid'

      doro_module.upcase!

      puts "[" + "+".red + "]" + " The #{doro_module} module is shutting now.."

      if pid_file and File.exist? pid_file
        pid = Integer(File.read(pid_file))
        Process.kill(-2,-pid)
        puts "[" + "+".red + "]" + " The #{doro_module} module (PID #{pid}) was terminated"
      else
        puts "[" + "+".red + "]" +  "Can't find PID file, is #{doro_module} really running?"
      end
    end

    def init_db(ddl=DoroSettings.dorothive[:ddl], force=false)
      LOGGER.warn "DB", "The database is going to be initialized with the file #{ddl}. If the Dorothive is already present, " + "all its data will be lost".red + ". Continue?(write yes)"
      answ = "yes"
      answ = gets.chop unless force

      if answ == "yes"
        begin
          #ugly, I know, but couldn't find a better and easier way..
          LOGGER.info "DB", "Creating DB #{DoroSettings.dorothive[:dbname]}"
          if system "sh -c 'createdb -h #{DoroSettings.dorothive[:dbhost]} -U #{DoroSettings.dorothive[:dbuser]} -e #{DoroSettings.dorothive[:dbname]} 1> /dev/null'"
            LOGGER.info "DB", "Importing the dorothive DDL from #{ddl}"
            system "sh -c  'psql -d #{DoroSettings.dorothive[:dbname]} -h #{DoroSettings.dorothive[:dbhost]} -U #{DoroSettings.dorothive[:dbuser]} -f #{ddl} 1> /dev/null'"
          else
            raise 'An error occurred'
          end

          LOGGER.info "DB", "Database correctly initialized. Now you can restart Dorothy!"
        rescue => e
          LOGGER.error "DB", $!
          LOGGER.debug "DB", e.inspect
        end
      else
        LOGGER.error "DB", "Database untouched, quitting."
      end
    end


  end

  module Ssh

    extend self

    def download(host, user, pass, file, dest, port=22)
      Net::SSH.start(host, user, :password => pass, :port =>port) do |ssh|
        ssh.scp.download! file, dest
      end
    end
  end

  module QueueManager
    extend self

    def add(f, sourceinfo, profile, priority, mail_id=nil)

      bin = Loadmalw.new(f)

      if bin.size == 0  || bin.sha.empty?
        LOGGER.warn "BFM", "Warning - Empty file #{bin.filename}, deleting and skipping.."
        FileUtils.rm bin.binpath
        return false
      end

      begin
        push_malw(bin, sourceinfo, profile, priority, mail_id)
      rescue => e
        LOGGER.error "DB", $!
        LOGGER.debug "DB", e.backtrace
        raise e
      end

    end

    #push the binary meta info into the DB
    def push_malw(bin, sourceinfo, profile, priority, mail_id)

      db = Insertdb.new
      db.begin_t

      unless db.select("samples", "sha256", bin.sha).one?                         #is bin.sha already present in my db?
        samplevalues = [bin.sha, bin.size, bin.binpath_repo, bin.filename, bin.md5, bin.type ]

        if db.insert("samples", samplevalues)                                     #no it isn't, insert it
          #Move the binary to the bin repo
          LOGGER.debug "BFM", "Moving file from the source's directory to the Dorothy's repository"
          FileUtils.mv(bin.binpath,bin.binpath_repo, :force => true)
        else
          raise "A DB error occurred"
        end

      else                                                                                #yes it is, don't insert in sample table
        date = db.select("sightings", "sample", bin.sha).first["date"]
        LOGGER.warn "BFM", "The binary #{bin.sha} was already added on #{date}"
        FileUtils.rm bin.binpath
      end


      #Add to sighting
      sigh_id = db.get_sighting_id
      sighvalues = [bin.sha, db.check_source_db(sourceinfo)["id"], bin.ctime, sigh_id, mail_id]
      raise "A DB error occurred" unless db.insert("sightings", sighvalues)

      # explanation: I don't want to insert the same malware twice but I do want to
      # insert the sighting value anyway ("the malware X has been downloaded 1 time but
      # has been spoted 32 times")

      #Add to the queue
      @id = db.analysis_queue_add(bin.sha, sourceinfo, bin.filename, profile, priority, nil, sigh_id )

      db.commit
      db.close

      @id

    end
  end

  class Insertdb

    def initialize
      @db = PGconn.open(:host=> DoroSettings.dorothive[:dbhost], :dbname=>DoroSettings.dorothive[:dbname], :user=>DoroSettings.dorothive[:dbuser], :password=>DoroSettings.dorothive[:dbpass])
    end

    def begin_t
      @db.exec("BEGIN")
    end

    def commit
      @db.exec("COMMIT")
    end

    def status
      @db.transaction_status
    end

    def close
      @db.close
    end

    def rollback
      LOGGER.error "DB", "DB ROLLBACK"
      @db.exec("ROLLBACK")
    end


    def insert(table,values)
      n = 1
      @sqlstring = ""

      values.each { |value|
        if value == "default"
          value1 = value
        elsif value == "null"
          value1 = value
        elsif value == nil
          value1 = "null"
        elsif value == "lastval()"
          value1 = value
        elsif value =~ /currval/
          value1 = value
        elsif table == "sys_procs"   #avoiding noising escape-issue for \u
          value1 = "E'#{value.inspect}'"
        else
          #if present, remove ""
          value.gsub! /^"|"$/, '' if values.class.inspect == "String"
          value1 = "E'#{value}'"
        end
        if n == values.size
          @sqlstring << value1
        elsif
        @sqlstring << value1 + ","
        end
        n += 1
      }
      #p "Inserting in dorothy.#{table}:"
      #p "#{@sqlstring}"

      begin
        @db.exec("INSERT into dorothy.#{table} values (#{@sqlstring})")
      rescue PG::Error => err
        LOGGER.error "DB", err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
        #self.rollback
        return false
        #exit 1
      end

      #p "Insertion OK"

    end

    def raw_insert(table, data)
      begin
        @db.exec("INSERT into dorothy.#{table} values (#{data})")
      rescue PG::Error => err
        LOGGER.error "DB", err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
        #self.rollback
        return false
        #exit 1
      end
    end

    def select(table, column, value, column2=nil, value2=nil, column3=nil, value3=nil)
      column2&&value2 ? ( column3&&value3 ? chk = @db.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}' AND #{column2} = '#{value2}' AND #{column3} = '#{value3}' ") : chk = @db.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}' AND #{column2} = '#{value2}'")) : chk = @db.exec("SELECT * from dorothy.#{table} where #{column} = '#{value}'")

      #puts ".::WARNING #{value} already present in dorothy.#{table}".red.bold if chk
      return chk
    end

    def get_anal_id
      @db.exec("SELECT nextval('dorothy.analyses_id_seq')").first["nextval"].to_i
    end

    def get_email_id
      @db.exec("SELECT nextval('dorothy.emails_id_seq')").first["nextval"].to_i
    end

    def get_sighting_id
      @db.exec("SELECT nextval('dorothy.sightings_id_seq')").first["nextval"].to_i
    end

    def get_curr_queue_id
      @db.exec("SELECT currval('dorothy.queue_id_seq')").first["currval"].to_i
    end


    def self.escape_bytea(data)
      escaped = PGconn.escape_bytea data
      return escaped
    end

    def table_empty?(table)
      @db.exec("SELECT CASE WHEN EXISTS (SELECT * FROM dorothy.#{table} LIMIT 1) THEN FALSE ELSE TRUE END").first["case"] == "t" ? true : false
    end

    def update_sample_path(sample, path)
      @db.exec("UPDATE dorothy.samples set path = '#{path}' where sha256 = '#{sample}'")
    end

    def set_analyzed(hash)
      @db.exec("UPDATE dorothy.traffic_dumps set parsed = true where sha256 = '#{hash}'")
    end

    def find_seq(seq)
      @db.exec("SELECT currval('dorothy.#{seq}')")
    end

    def flush_table(table)
      @db.exec("TRUNCATE dorothy.#{table} CASCADE")
    end

    def malware_list
      malwares = []
      @db.exec("SELECT samples.sha256 FROM dorothy.samples").each do |q|
        malwares.push q
      end
      malwares
    end

    def push_email_data(m, forwarded_by='null')
      #m is a message object from the Mail class
      id = get_email_id
      values = " '#{m.from[0]}', E'#{m.subject}', E'#{Insertdb.escape_bytea(m.raw_source)}', '#{id}', null, null, null, null, null, '#{Util.get_time(m.date)}', '#{m.message_id}', '#{m.has_attachments?}', '#{m.charset}', '#{Digest::SHA2.hexdigest(m.body.raw_source)}', #{forwarded_by}"
      raise "A DB error occurred while adding data into the emails table" unless  raw_insert('emails', values)

      #adding receivers
      #TO
      m.to_addrs.each  {|addr|  raise "A DB error occurred while adding data into the emails_receivers table" unless insert('email_receivers', [addr, id, 'to'])}
      #CC
      m.cc_addrs.each  {|addr|  raise "A DB error occurred while adding data into the emails_receivers table" unless insert('email_receivers', [addr, id, 'cc'])}


      id
    end

    def analysis_queue_add(bin, source, filename, profile='default', priority=0, user='system', sigh_id)
      id =  "default"
      time = Util.get_time
      values = [id, time, bin, priority, profile, check_source_db(source)["id"], user, filename, "pending", sigh_id.to_i]

      raise "A DB error occurred while adding data into the anaylsis_queue table" unless insert("analysis_queue", values)

      @id = get_curr_queue_id    #race condition?
    end

    def analysis_queue_mark(id,status)
      begin
        @db.exec("UPDATE dorothy.analysis_queue set status = '#{status}' where id = '#{id}'")
      end
    rescue PG::Error => err
      LOGGER.error "DB","Error while updating analysis_queue_mark_analysed table:  " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      raise err
    end

    def analysis_queue_pull
      @bins = []
      begin
        @db.exec("SELECT analysis_queue.id, analysis_queue.binary, samples.path, analysis_queue.filename, analysis_queue.priority, analysis_queue.profile, analysis_queue.source, analysis_queue.date FROM dorothy.analysis_queue, dorothy.samples WHERE analysis_queue.binary = samples.sha256 AND analysis_queue.status = 'pending' ORDER BY analysis_queue.priority DESC, analysis_queue.id ASC").each do |q|
          @bins.push q
        end
      rescue PG::Error => err
        LOGGER.error "DB","Error while fetching traffic_dumps table " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      end
      @bins
    end

    #Mark all the pending analyses as analyzed
    def analysis_queue_mark_all
      analysis_queue_pull.each do |qentry|
        analysis_queue_mark(qentry["id"], "analysed")
      end
      LOGGER.debug "DB", "Pending analyses removed from the queue"
    end

    #List pending analyses
    def analysis_queue_view
      LOGGER.info "QUEUE", "Pending analyses:"
      puts "\n[" + "-".red + "] " + "\tID\tAdded\t\t\tSource\tFilename"
      puts "[" + "-".red + "] " + "\t--\t-----\t\t\t------\t--------\n"

      analysis_queue_pull.each do |qentry|
        puts "[" + "*".red + "] " + "\t#{qentry["id"]}\t#{qentry["date"]}\t#{qentry["source"]}\t#{qentry["filename"]}"
        puts ""
      end
    end

    def find_last_conf_chksum(conf)
      begin
        r = @db.exec("SELECT cfg_chk.md5_chksum FROM dorothy.cfg_chk WHERE cfg_chk.conf_file = '#{conf}' ORDER BY cfg_chk.id DESC LIMIT 1")
        r.first.nil? ? nil : r.first["md5_chksum"]
      rescue PG::Error => err
        LOGGER.error "DB","Error while fetching conf_chk table " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      end
    end

    def disable_source_db(id)
      begin
        @db.exec("UPDATE dorothy.sources set disabled = true, last_modified = '#{Util.get_time}'where id = '#{id}'")
        true
      rescue PG::Error => err
        LOGGER.error "DB", "An error occurred while adding data into sources table " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
        false
      end
    end

    def check_source_db(source)
      begin
        r = @db.exec("SELECT sources.id, sources.sname, sources.stype, sources.host, sources.localdir FROM dorothy.sources WHERE sources.disabled = FALSE AND sources.sname = '#{source}'")
        r.first.nil? ? nil : r.first
      rescue PG::Error => err
        LOGGER.error "DB", "An error occurred while accessing sources table" + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      end
    end

    def enabled_sources_db
      begin
        r = @db.exec("SELECT sources.id, sources.sname, sources.stype, sources.host, sources.localdir FROM dorothy.sources WHERE sources.disabled = FALSE")
        r.first.nil? ? nil : r
      rescue PG::Error => err
        LOGGER.error "DB", "An error occurred while accessing sources table" + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      end
    end


    def check_sources_modifications(source)

      db_sources = enabled_sources_db

      unless db_sources.nil?
        db_sources.each do |s|
          unless source.has_key?(s["sname"])
            LOGGER.warn "CheckCONF", "#{s["sname"]} was removed, disabling"
            disable_source_db(s["id"])
          end
        end
      end


      source.each do |k,v|
          values = ['default', k, v["type"], 'default', v["host"], 0, Util.get_time, Util.get_time, v["localdir"]]

          db_source = check_source_db(k)
          if db_source.nil?
            LOGGER.warn "CheckCONF", "#{k} Added"
            insert("sources", values)
          elsif v["type"] != db_source["stype"] || v["host"] != db_source["host"] || v["localdir"] != db_source["localdir"]

            LOGGER.warn "CheckCONF", "#{k} MODIFIED"

            disable_source_db(db_source["id"])
            LOGGER.warn "CheckCONF", "#{k} DISABLED"

            insert("sources", values)
            LOGGER.warn "CheckCONF", "#{k} ADDED"
          end
        end
    end



    def find_pcap
      @pcaps = []
      begin
        @db.exec("SELECT traffic_dumps.sha256, traffic_dumps.pcapr_id, traffic_dumps.size, traffic_dumps.binary, traffic_dumps.parsed, samples.md5 as \"sample\", analyses.date as \"date\", analyses.id as \"anal_id\" FROM dorothy.traffic_dumps, dorothy.samples, dorothy.analyses WHERE analyses.traffic_dump = traffic_dumps.sha256 AND analyses.sample = samples.sha256 AND traffic_dumps.parsed = false").each do |q|
          @pcaps.push q
        end
      rescue PG::Error => err
        LOGGER.error "DB","Error while fetching traffic_dumps table " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
      end

    end

    def get_curr_malwares_id
      @db.exec("SELECT nextval('dorothy.malwares_id_seq')").first["nextval"].to_i
    end

    def find_vm(os_type, os_version, os_lang)
      vm = @db.exec("SELECT id, hostname, ipaddress, username, password FROM dorothy.sandboxes where os = '#{os_type}' AND version = '#{os_version}' AND os_lang = '#{os_lang}' AND is_available is true").first
      if vm.nil?
        LOGGER.debug "DB","At this time there are no free VM available that matches the selected profile"  if VERBOSE
        return false
      else
        @db.exec("UPDATE dorothy.sandboxes set is_available = false where id = '#{vm["id"]}'")
        return vm["id"].to_i, vm["hostname"], vm["ipaddress"], vm["username"], vm["password"]
      end
    end

    def free_vm(vmid)
      r = @db.exec("SELECT hostname FROM dorothy.sandboxes where id = '#{vmid}' AND is_available is false")
      if !r.first.nil? #check if the issued VM is already free
        begin
          @db.exec("UPDATE dorothy.sandboxes set is_available = true where id = '#{vmid}'")
          LOGGER.info "DB", "VM #{vmid} succesfully released"
          return true
        rescue PG::Error => err
          LOGGER.error "DB", "An error occurred while releasing the VM " + err.result.error_field( PG::Result::PG_DIAG_MESSAGE_PRIMARY )
          return false
        end
      else
        LOGGER.warn "DB", "Dorothy is trying to release the VM #{vmid} that is already available!!"
        return false
      end
    end

    def vm_init
      @db.exec("UPDATE dorothy.sandboxes set is_available = true")
      LOGGER.debug "DB", "All VM are now available"
      #TODO - revert them too?
    end

  end

##CLASS MAILER FROM SALVATORE
  class Mailer
    attr_reader :n_emails
    attr_reader :delete_once_downloaded

    def initialize(account)

      @n_emails = account[:n_emails]
      @delete_once_downloaded = account[:delete_once_downloaded]

      @mailbox = Mail.defaults do
        retriever_method :pop3,
                         :address    => account[:address],
                         :user_name  => account[:username],
                         :password   => account[:password],
                         :port       => account[:port],
                         :enable_ssl => account[:ssl]
      end
    end

    def read_from_string(string)
      Mail.read_from_string(string)
    end


    def get_emails
      begin
        @emails = @mailbox.find(:what => :first, :count => @n_emails, :order => :asc, :delete_after_find => @delete_once_downloaded)
      rescue Net::POPError => e
        LOGGER.error "MAIL", e.message
        raise
      end

    end


  end

  class Loadmalw
    attr_reader :pcaprid
    attr_reader :type
    attr_reader :dbtype
    attr_accessor :sha
    attr_reader :md5
    attr_reader :binpath
    attr_reader :filename

    #Here i'm sure that the file has an extension and can be executed by windows
    attr_reader :full_filename
    attr_reader :ctime
    attr_reader :size
    attr_reader :pcapsize
    attr_reader :extension

    #Used for storing info about where the binary comes from (if needed)
    attr_accessor :sourceinfo

    #binaries' repository where all the samples go.
    attr_reader :binpath_repo

    #Analysis folder where the files will be created
    attr_accessor :dir_pcap
    attr_accessor :dir_bin
    attr_accessor :dir_screens
    attr_accessor :dir_downloads

    def initialize(file, change_filename=nil)

      fm = FileMagic.new
      @binpath = file
      change_filename ||=  File.basename(file).strip

      @filename = change_filename
      @extension = File.extname(change_filename)[1..-1]


      @md5 = Digest::MD5.hexdigest(File.read(file))
      @sha = Digest::SHA2.hexdigest(File.read(file))


      @sourceinfo = nil

      @binpath_repo = DoroSettings.env[:bins_repository] + '/' + @md5

      timetmp = File.ctime(file)
      @ctime= timetmp.strftime("%m/%d/%y %H:%M:%S")
      @type = fm.file(file)


      if @extension.nil?    #no extension, trying to put the right one..
        case @type
          when /^PE32/ then
            @extension = (@type =~ /DLL/ ? "dll" : "exe")
          when /^COM/ then
            @extension = "exe"
          when /^MS-DOS/ then
            @extension = "bat"
          when /^HTML/ then
            @extension = "html"
          else
            @extension = "unknown"
        end
        @full_filename = @filename + "." +  @extension
      else
        @full_filename = @filename
      end

      @size = File.size(file)
    end



    def self.calc_pcaprid(file, size)
      #t = file.split('/')
      #dumpname = t[t.length - 1]
      @pcaprid = Digest::MD5.new
      @pcaprid << "#{file}:#{size}"
      @pcaprid = @pcaprid.dup.to_s.rstrip
    end


  end


end
