
module Dorothy

class DorothyMAM

  def initialize(server,user,pass,vmname,guestuser,guestpass)

    begin
      vim = RbVmomi::VIM.connect(:host => server , :user => user, :password=> pass, :insecure => true)
    rescue Timeout::Error
      LOGGER.fatal "Fail to connect to the ESXi server #{server} - TimeOut (Are you sure that is the right address?)"
      exit!(1)
    end

    @server = server

    dc = vim.serviceInstance.find_datacenter
    @vm = dc.find_vm(vmname)
    om = vim.serviceContent.guestOperationsManager
    am = om.authManager
    @pm = om.processManager
    @fm = om.fileManager

    #AUTHENTICATION
    guestauth = {:interactiveSession => false, :username => guestuser, :password => guestpass}
    @auth=RbVmomi::VIM::NamePasswordAuthentication(guestauth)
    abort "[ERROR] User not authenticated" if am.ValidateCredentialsInGuest(:vm => @vm, :auth => @auth) != nil

  end

  def start_vm(vmname)
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
      abort "Fail to copy the file #{file} to #{@vm}: #{$!}"
    end

  end

  def exec_file(filename, dll=false)
    filepath = "C:\\#{filename}"

    if dll
      cmd = { :programPath => "C:\\windows\\system32\\rundll32.exe", :arguments => filepath}
      LOGGER.info ".:: Executing dll #{filename}"

    else
      cmd = { :programPath => filepath, :arguments => "" }
    end


    pid = @pm.StartProgramInGuest(:vm => @vm , :auth => @auth, :spec => cmd )
    #puts "Program executed with id #{pid}:"
    #puts @pm.ListProcessesInGuest(:vm => @vm, :auth => @auth, :pids => pid.to_a).inspect

    return Array(pid)
  end


  def check_internet
    testbatch = "C:\\test_ping.bat" #TODO CONST
    cmd = { :programPath => testbatch, :arguments => "" }
    pid = @pm.StartProgramInGuest(:vm => @vm , :auth => @auth, :spec => cmd )
    sleep 3 #timeout in case that internet is not reachable
    status = get_status(pid)
    raise StandardError, "Ping exited 0" if status != 0
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

class Loadmalw
  attr_reader :pcaprid
  attr_reader :type
  attr_reader :dbtype
  attr_reader :sha
  attr_reader :md5
  attr_reader :binpath
  attr_reader :filename
  attr_reader :ctime
  attr_reader :size
  attr_reader :pcapsize
  attr_reader :extension
  attr_accessor :sourceinfo   #used for storing info about where the binary come from (if needed)

  #	attr_accessor :dir_home
  attr_reader :dir_pcap
  attr_reader :dir_bin
  attr_reader :dir_screens
  attr_reader :dir_downloads

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
    @md5 = @md5.to_s
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
    @dir_pcap = "#{ANALYSIS_DIR}/#{@md5}/pcap/"
    @dir_bin = "#{ANALYSIS_DIR}/#{@md5}/bin/"
    @dir_screens = "#{ANALYSIS_DIR}/#{@md5}/screens/"
    @dir_downloads = "#{ANALYSIS_DIR}/#{@md5}/downloads/"
  end



  def self.calc_pcaprid(file, size)
    #t = file.split('/')
    #dumpname = t[t.length - 1]
    @pcaprid = Digest::MD5.new
    @pcaprid << "#{file}:#{size}"
    @pcaprid =@pcaprid.dup.to_s
  end


end

class DorothyNAM
  attr_accessor :server
  attr_accessor :user
  attr_accessor :pass
  attr_accessor :pcaphome

  #Create a dotothy user in the NSM machine, and add this line to the sudoers :
  #   dorothy  ALL = NOPASSWD: /usr/sbin/tcpdump, /bin/kill
  #

  def initialize(mamdata)
    @server = mamdata[0]
    @user= mamdata[1]
    @pass= mamdata[2]
    @pcaphome = mamdata[3]
  end

  def start_sniffer(vmaddress, name)
    Net::SSH.start(@server, @user, :password => @pass) do |@ssh|
     # @ssh.exec "nohup sudo tcpdump -i eth0 -s 1514 -w ~/pcaps/#{name}.pcap host #{vmaddress} > blah.log 2>&1 & "
      @ssh.exec "nohup sudo tcpdump -i en0 -s 1514 -w ~/pcaps/#{name}.pcap host #{vmaddress} > blah.log 2>&1 & "
      t = @ssh.exec!"ps aux |grep #{vmaddress}|grep -v grep|grep -v bash"
      #puts "MAM Process GREP: " + t
      pid = t.split(" ")[1]
      return pid
    end
  end

  #TODO: delete and use only the function download()
  def download_pcap(pcap,dest)
    Net::SSH.start(@server, @user, :password => @pass) do |ssh|
      #puts "Downloading #{@pcaphome}/#{pcap}"
      ssh.scp.download! "#{@pcaphome}/#{pcap}", dest
    end
  end

  #TODO: move to Utility.rb library?
  def download(file,dest)
    Net::SSH.start(@server, @user, :password => @pass) do |ssh|
      ssh.scp.download! file, dest
    end
  end

  def stop_sniffer(pid)
    Net::SSH.start(@server, @user, :password => @pass) do |ssh|
      ssh.exec "sudo kill -2 #{pid}"
      #LOGGER.info "[NAM]".yellow + "Tcpdump instance #{pid} stopped"
    end
  end

end

end




