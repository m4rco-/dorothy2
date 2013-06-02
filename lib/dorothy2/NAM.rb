module Dorothy

  #Dorothy module-class for controlling the network sniffers i.e. tcpdump instances
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
