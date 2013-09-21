# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.

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
        MANUAL ? not_rdp = "and not port 3389" : not_rdp = ""
        @ssh.exec "nohup sudo tcpdump -i #{interface} -s 1514 -w #{pcaphome}/#{name}.pcap host #{vmaddress} #{not_rdp} 2> log.tmp  & "

        begin
          t = @ssh.exec!"ps aux |grep #{name}|grep -v grep|grep -v bash"
          pid = t.split(" ")[1]
        rescue
          r = 0
          if r <= 2
            r = r+1
            LOGGER.warn "NSM", " NAM has failed to catch the Tcpdump PID, retry n. #{r}/3"
            sleep 2
            retry
          end
          LOGGER.warn "NSM", " NAM has failed to catch the Tcpdump PID, retry n. #{r}/3"
          raise
        end
        return pid.to_i
      end
    end

    def init_sniffer
      Net::SSH.start(@server, @user, :password => @pass, :port =>@port) do |ssh|
        ssh.exec "sudo killall tcpdump"
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
