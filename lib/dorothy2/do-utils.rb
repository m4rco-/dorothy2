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

    def exists?(file)
      File.exist?(file)
    end

    def init_db(ddl=DoroSettings.dorothive[:ddl], force=false)
      LOGGER.warn "DB", "The database is going to be initialized with the file #{ddl}. If the Dorothive is already present, " + "all its data will be lost".red + ". Continue?(write yes)"
      answ = "yes"
      answ = gets.chop unless force

      if answ == "yes"
        begin
          #ugly, I know, but couldn't find a better and easier way..
          raise 'An error occurred' unless system "sh -c 'psql -h #{DoroSettings.dorothive[:dbhost]} -U #{DoroSettings.dorothive[:dbuser]} -f #{ddl} 1> /dev/null'"
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
      rescue => e
        LOGGER.debug "DB", $!
        LOGGER.debug "DB", e.inspect
        #self.rollback
        return false
        #exit 1
      end

      #p "Insertion OK"

    end

    def raw_insert(table, data)
      begin
        @db.exec("INSERT into dorothy.#{table} values (#{data})")
      rescue
        LOGGER.error "DB", "#{$!}"
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

    def self.escape_bytea(data)
      escaped = PGconn.escape_bytea data
      return escaped
    end

    def table_empty?(table)
      @db.exec("SELECT CASE WHEN EXISTS (SELECT * FROM dorothy.#{table} LIMIT 1) THEN FALSE ELSE TRUE END").first["case"] == "t" ? true : false
    end

    def update_proto(role, ip)
      @db.exec("UPDATE dorothy.host_roles set app_protocol = '#{proto}' where id = currval('connections_id_seq')")
    end

    def set_analyzed(hash)
      @db.exec("UPDATE dorothy.traffic_dumps set parsed = true where hash = '#{hash}'")
    end

    def find_seq(seq)
      @db.exec("SELECT currval('dorothy.#{seq}')")
    end

    def flush_table(table)
      @db.exec("TRUNCATE dorothy.#{table} CASCADE")
    end

    def malware_list
      malwares = []
      @db.exec("SELECT samples.hash FROM dorothy.samples").each do |q|
        malwares.push q
      end
      return malwares
    end

    def find_pcap
      @pcaps = []
      begin
        @db.exec("SELECT traffic_dumps.hash, traffic_dumps.pcapr_id, traffic_dumps.size, traffic_dumps.binary, traffic_dumps.parsed, samples.md5 as \"sample\", analyses.date as \"date\", analyses.id as \"anal_id\" FROM dorothy.traffic_dumps, dorothy.samples, dorothy.analyses WHERE analyses.traffic_dump = traffic_dumps.hash AND analyses.sample = samples.hash AND traffic_dumps.parsed = false").each do |q|
          @pcaps.push q
        end
      rescue
        LOGGER.error "DB","Error while fetching traffic_dumps table\n " + $!
      end

    end

    def find_vm
      vm = @db.exec("SELECT id, hostname, ipaddress, username, password FROM dorothy.sandboxes where is_available is true").first
      if vm.nil?
        LOGGER.debug "DB","At this time there are no free VM available"  if VERBOSE
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
        rescue
          LOGGER.error "DB", "An error occurred while releasing the VM"
          LOGGER.debug "DB", $!
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

  class Loadmalw
    attr_reader :pcaprid
    attr_reader :type
    attr_reader :dbtype
    attr_accessor :sha
    attr_reader :md5
    attr_reader :binpath
    attr_reader :filename
    attr_reader :full_filename  #here i'm sure that the file has an extension and can be executed by windows
    attr_reader :ctime
    attr_reader :size
    attr_reader :pcapsize
    attr_reader :extension
    attr_accessor :sourceinfo   #used for storing info about where the binary come from (if needed)

    #	attr_accessor :dir_home
    attr_accessor :dir_pcap
    attr_accessor :dir_bin
    attr_accessor :dir_screens
    attr_accessor :dir_downloads

    def initialize(file)

      fm = FileMagic.new
      sha = Digest::SHA2.new
      md5 = Digest::MD5.new
      @binpath = file
      @filename = File.basename(file)
      @extension = File.extname(file)[1..-1]

      File.open(file, 'rb') do |fh1|
        while buffer1 = fh1.read(1024)
          @sha = sha << buffer1
          @md5 = md5 << buffer1
        end
      end

      @sha = @sha.to_s
      @md5 = @md5.to_s.rstrip
      @sourceinfo = nil

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