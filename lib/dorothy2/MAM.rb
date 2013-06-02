# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

module Dorothy

  class Doro_VSM

    #Creates a new instance for communicating with ESX through the vSpere5's API
    class ESX

      def initialize(server,user,pass,vmname,guestuser,guestpass)

        begin
          vim = RbVmomi::VIM.connect(:host => server , :user => user, :password=> pass, :insecure => true)
        rescue Timeout::Error
          raise "Fail to connect to the ESXi server #{server} - TimeOut (Are you sure that is the right address?)"
        end

        @server = server
        dc = vim.serviceInstance.find_datacenter
        @vm = dc.find_vm(vmname)

        raise "Virtual Machine #{vmname} not present within ESX!!" if @vm.nil?

        om = vim.serviceContent.guestOperationsManager
        am = om.authManager
        @pm = om.processManager
        @fm = om.fileManager

        #AUTHENTICATION
        guestauth = {:interactiveSession => false, :username => guestuser, :password => guestpass}
        @auth=RbVmomi::VIM::NamePasswordAuthentication(guestauth)
        abort if am.ValidateCredentialsInGuest(:vm => @vm, :auth => @auth) != nil
      end

      def revert_vm
        @vm.RevertToCurrentSnapshot_Task
      end

      def copy_file(filename,file)
        filepath = "C:\\#{filename}" #put md5 hash

        begin
          url = @fm.InitiateFileTransferToGuest(:vm => @vm, :auth=> @auth, :guestFilePath=> filepath, :fileSize => file.size, :fileAttributes => '', :overwrite => true).sub('*:443', @server)

          RestClient.put(url, file)

        rescue RbVmomi::Fault
          LOGGER.error "VSM", "Fail to copy the file #{file} to #{@vm}: #{$!}"
          abort
        end

      end

      def exec_file(filename, arguments="")
        filepath = "C:\\#{filename}"

        if File.extname(filename) == ".dll"
          cmd = { :programPath => "C:\\windows\\system32\\rundll32.exe", :arguments => filepath}
          LOGGER.info "VSM", ".:: Executing dll #{filename}"

        else
          cmd = { :programPath => filepath, :arguments => arguments }
        end

        pid = @pm.StartProgramInGuest(:vm => @vm , :auth => @auth, :spec => cmd )
        pid.to_i
      end

      def check_internet
         exec_file("windows\\system32\\ping.exe", "-n 1 www.google.com")  #make www.google.com customizable, move to doroconf
      end


      def get_status(pid)
        p = @pm.ListProcessesInGuest(:vm => @vm , :auth => @auth, :pids => Array(pid) ).inspect
        status = (p =~ /exitCode=>([0-9])/ ? $1.to_i : nil )
        return status
      end


      def screenshot
        a = @vm.CreateScreenshot_Task.wait_for_completion.split(" ")
        ds = @vm.datastore.find { |ds| ds.name  == a[0].delete("[]")}
        screenpath = "/vmfs/volumes/" + a[0].delete("[]") + "/" + a[1]
        return screenpath
      end
    end

    #TODO. Example of how a new VSM´s structure should look like
    class VirtualBox
      def initialize

      end

      def revert_vm

      end

      def copy_file

      end

      def exec_file

      end

      def check_internet

      end

      def get_status

      end

      def screenshot

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
      @filename = File.basename file
      @extension = File.extname file
      @dbtype = "null"  #TODO: remove type column in sample table

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

      if @extension.empty?    #no extension, trying to put the right one..
        case @type
          when /^PE32/ then
            @extension = (@type =~ /DLL/ ? ".dll" : ".exe")
          when /^MS-DOS/ then
            @extension = ".bat"
          when /^HTML/ then
            @extension = ".html"
          else
            @extension = nil
        end
      end


      @size = File.size(file)
      #  @dir_pcap = "#{ANALYSIS_DIR}/#{@md5}/pcap/"
      #  @dir_bin = "#{ANALYSIS_DIR}/#{@md5}/bin/"
      #  @dir_screens = "#{ANALYSIS_DIR}/#{@md5}/screens/"
      #  @dir_downloads = "#{ANALYSIS_DIR}/#{@md5}/downloads/"
    end



    def self.calc_pcaprid(file, size)
      #t = file.split('/')
      #dumpname = t[t.length - 1]
      @pcaprid = Digest::MD5.new
      @pcaprid << "#{file}:#{size}"
      @pcaprid = @pcaprid.dup.to_s.rstrip
    end


  end

  class Doro_NAM

    #Create a dotothy user in the NSM machine, and add this line to the sudoers :
    #   dorothy  ALL = NOPASSWD: /usr/sbin/tcpdump, /bin/kill
    #

    def initialize(namdata)
      @server = namdata[:host]
      @user= namdata[:user]
      @pass= namdata[:pass]
      @port = namdata[:port]
    end

    def start_sniffer(vmaddress, interface, name, pcaphome)
      Net::SSH.start(@server, @user, :password => @pass, :port =>@port) do |@ssh|
        # @ssh.exec "nohup sudo tcpdump -i eth0 -s 1514 -w ~/pcaps/#{name}.pcap host #{vmaddress} > blah.log 2>&1 & "
        @ssh.exec "nohup sudo tcpdump -i #{interface} -s 1514 -w #{pcaphome}/#{name}.pcap host #{vmaddress} > log.tmp 2>&1 & "
        t = @ssh.exec!"ps aux |grep #{vmaddress}|grep -v grep|grep -v bash"
        pid = t.split(" ")[1]
        return pid.to_i
      end
    end

    def stop_sniffer(pid)
      Net::SSH.start(@server, @user, :password => @pass, :port =>@port) do |ssh|
        ssh.exec "sudo kill -2 #{pid}"
        #LOGGER.info "[NAM]".yellow + "Tcpdump instance #{pid} stopped"
      end
    end

  end

end




