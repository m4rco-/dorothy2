# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.

module Dorothy

  #Dorothy module-class for managig the virtual sandboxes
  class Doro_VSM

    #ESX5 interface
    class ESX

      #Creates a new instance for communicating with ESX through the vSpere5's API
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

    #Empty method for showing how it could be easy to extend the dorothy's VSM with another virtual manager.
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


end




