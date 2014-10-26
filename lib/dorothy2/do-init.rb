#!/bin/env ruby
# encoding: utf-8

# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/
# See the file 'LICENSE' for copying permission.
require 'fileutils'

module Dorothy

  module DoroConfig

    extend self

    def init_home(home)
      puts "[INIT]".yellow + " Creating Directoy structure in #{home}"
      Dir.mkdir(home) unless Util.exists?("#{home}")
      unless Util.exists?("#{home}/opt")
        Dir.mkdir("#{home}/opt")
        Dir.mkdir("#{home}/opt/bins")
        Dir.mkdir("#{home}/opt/analyzed")
        Dir.mkdir("#{home}/opt/analyzed/bins")
      end
      unless Util.exists?("#{home}/etc")
        Dir.mkdir("#{home}/etc")
        Dir.mkdir("#{home}/etc/geo")
      end
      unless Util.exists?("#{home}/var")
        Dir.mkdir("#{home}/var")
        Dir.mkdir("#{home}/var/log")
      end
      puts "[INIT]".yellow + " Done\n\n"
    end

    def create

      puts "
      [WARNING]".red + " It seems that the Dorothy configuration file is not present,
                please answer to the following question in order to create it now.
      "

      correct = false

      until correct

        conf = Hash.new
        conf["sandbox"] = Hash.new
        conf["env"] = Hash.new
        conf["dorothive"] = Hash.new
        conf["nam"] = Hash.new
        conf["virustotal"] = Hash.new
        conf["esx"] = Hash.new
        conf["pcapr"] = Hash.new
        conf["wgui"] = Hash.new
        conf["bfm"] = Hash.new


        ################################################
        ###DOROTHY ENVIRONMENT
        ################################################

        puts "\n######### [" + " Dorothy Environment settings ".red + "] #########"
        puts "Please insert the home folder for dorothy [#{File.expand_path("~")}/Dorothy]"
        conf["env"]["home"] = (t = gets.chop).empty? ? "#{File.expand_path("~")}/Dorothy" : t

        home = conf["env"]["home"]

        puts "The Dorothy home directory is #{home}"

        conf["env"]["pidfiles"] = "#{home}/var"
        conf["env"]["pidfile_parser"] = "#{home}/var/doroParser.pid"
        conf["env"]["analysis_dir"] = "#{home}/opt/analyzed"
        conf["env"]["bins_repository"] = "#{home}/opt/analyzed/bins"
        conf["env"]["geoip"] = "#{home}/etc/geo/GeoLiteCity.dat"
        conf["env"]["geoasn"] = "#{home}/etc/geo/GeoIPASNum.dat"
        conf["env"]["geoisp"] = "#{home}/etc/geo/GeoIPISP.dat"

        conf["env"]["sleeptime"] = 5

        conf["env"]["logfile"] = "#{home}/var/log/dorothy.log"
        conf["env"]["logfile_parser"] = "#{home}/var/log/parser.log"
        conf["env"]["loglevel"] = 0
        conf["env"]["logage"] = "weekly"


        ######################################################
        ###DOROTHIVE
        ######################################################

        puts "\n######### [" + " Dorothive (Dorothy DB) settings ".red + "] #########"

        puts "DB hostname/IP address [localhost]:"
        conf["dorothive"]["dbhost"] = (t = gets.chop).empty? ? "localhost" : t

        puts "DB Name [dorothive]:"
        conf["dorothive"]["dbname"] = (t = gets.chop).empty? ? "dorothive" : t

        puts "DB Username [postgres]:"
        conf["dorothive"]["dbuser"] = (t = gets.chop).empty? ? "postgres" : t

        puts "DB Password"
        conf["dorothive"]["dbpass"] = gets.chop

        conf["dorothive"]["ddl"] = "#{HOME}/etc/ddl/dorothive.ddl"

        ######################################################
        ###ESX
        ######################################################

        puts "######### [" + " ESX Environment settings ".red + "] #########"

        puts "Please insert the IP address of your ESX server"
        conf["esx"]["host"] = gets.chop

        puts "Please insert the ESX username"
        conf["esx"]["user"] = gets.chop

        puts "Please insert the ESX password"
        conf["esx"]["pass"] = gets.chop

        #################################################
        ###SANDBOX
        ################################################

        puts "\n######### [" + " Sandbox configuration settings ".red + "] #########"



        puts "Which is the sandox's network? [10.10.10.0/0]"
        conf["sandbox"]["network"] = (t = gets.chop).empty? ? "10.10.10.0/0" : t

        ######################################################
        ###NAM
        ######################################################

        puts "\n######### [" + " Network Analysis Module (NAM) configuration ".red + "] #########"

        puts "Please insert the information of the host that you will use for sniffing the Sandbox traffic"

        puts "IP Address:"
        conf["nam"]["host"] = gets.chop

        puts "Network interface for the network sniffing: [eth0]"
        conf["nam"]["interface"] = (t = gets.chop).empty? ? "eth0" : t

        puts "Username [dorothy] :"
        conf["nam"]["user"] = (t = gets.chop).empty? ? "dorothy" : t

        puts "Password:"
        conf["nam"]["pass"] = gets.chop

        puts "SSH Port [22] :"
        conf["nam"]["port"] = (t = gets.chop).empty? ? 22 : t.to_i

        puts "Folder where to store PCAP files [/home/#{conf["nam"]["user"]}/pcaps]"
        conf["nam"]["pcaphome"] = (t = gets.chop).empty? ? "/home/#{conf["nam"]["user"]}/pcaps" : t

        ######################################################
        ###PCAPR
        ######################################################

        puts "\n######### [" + " Pcapr configuration ".red + "] #########"

        puts "Are you going to use Pcapr on this machine? [yes] WARNING: Pcapr is only compatible with Linux "

        t = gets.chop
        if t.empty? || t == "y" || t == "yes"
          conf["pcapr"]["local"] = true
          puts "[WARNING]".yellow + " Be careful in setting Pcapr to scan #{conf["env"]["analysis_dir"]}"
          conf["pcapr"]["host"] = "localhost"
        else
          conf["pcapr"]["local"] = false
          puts "Pcapr Host [NAM: #{conf["nam"]["host"]}]:"
          conf["pcapr"]["host"] = (t = gets.chop).empty? ? conf["nam"]["host"] : t
        end

        puts "Pcapr HTTP Port [8080]:"
        conf["pcapr"]["port"] = (t = gets.chop).empty? ? 8080 : t.to_i


        ######################################################
        ###WebGUI
        ######################################################
        puts "\n######### [" + " Web GUI configuration ".red + "] #########"

        puts "IP Address used for listening. Use 0.0.0.0 to allow remote connections [localhost]:"
        conf["wgui"]["host"] = (t = gets.chop).empty? ? 'localhost' : t.to_s

        puts "TCP port [3435]:"
        conf["wgui"]["port"] = (t = gets.chop).empty? ? 3435 : t.to_i

        conf["wgui"]["environment"] = "production"
        conf["wgui"]["logfile"] = "#{home}/var/log/webgui.log"

        ######################################################
        ###Binaries Fetcher Module
        ######################################################
        puts "\n######### [" + " Binaries Fetcher Module ".red + "] #########"

        puts "How often the BFM should pool all the resources (sec)? [60]"
        conf["bfm"]["sleeptime"] = (t = gets.chop).empty? ? 60 : t.to_i


        ######################################################
        ###VIRUS TOTAL
        ######################################################

        puts "\n######### [" + " Virus Total API ".red + "] #########"

        puts "In order to retrieve Virus signatures, Dorothy needs to contact VirusTotal,\n please enter your VT API key here, if you don't have one yet, go here (or press enter):\nhttps://www.virustotal.com/en/#dlg-join "
        conf["virustotal"]["vtapikey"] = gets.chop

        puts "Enable test mode? In test mode dorothy will avoid to poll Virustotal [y]"

        t = gets.chop
        (t.empty? || t == "y" || t == "yes") ? conf["env"]["testmode"] = true : conf["env"]["testmode"] = false

        ##########CONF FINISHED##################

        puts "\n######### [" + " Configuration finished ".yellow + "] #########"
        puts "Confirm? [y]"

        t = gets.chop
        if t.empty? || t == "y" || t == "yes"
          begin
            self.init_home(home)
            File.open("#{File.expand_path("~")}/.dorothy.yml", 'w+') {|f| f.write(conf.to_yaml) }
            FileUtils.ln_s("#{File.expand_path("~")}/.dorothy.yml", "#{home}/etc/dorothy.yml") unless Util.exists?("#{home}/etc/dorothy.yml")

            correct = true
            puts "Configuration file has been saved in ~/.dorothy.conf and a symlink has been created in\n#{home}/etc/dorothy.yml for an easier edit."
            puts "\n######### [" + " Now you can restart dorothy, enjoy! ".yellow + "] #########"
          rescue => e
            puts e.inspect
            puts "[ERROR]".red + " Configuration aborted, please redo."
            FileUtils.rm("#{home}/etc/dorothy.yml")
          end
        else
          puts "Please reinsert the info"
          correct = false
        end

      end

    end


    def create_profiles(filename, sandbox=false, vtotal=nil)

      correct = false
      conf = Hash.new
      if sandbox

        conf['default'] = {}

        conf['default']['sleeptime'] = 60
        vtotal ? conf['default']['vtotal_query'] = true : conf['default']['vtotal_query'] = false


        conf['default']['screenshots'] = {}
        conf['default']['screenshots']['number'] = 2
        conf['default']['screenshots']['delay_first'] = 1
        conf['default']['screenshots']['delay_inbetween'] = 30



        conf['default']['OS'] = {}
        conf['default']['OS']['type'] = sandbox['os']
        conf['default']['OS']['version'] = sandbox['version']
        conf['default']['OS']['lang'] = sandbox['os_lang']



        conf['default']['extensions'] = {}

        %w(exe bat html rtf).each do |ext|
          conf['default']['extensions'][ext] = Hash.new
          conf['default']['extensions'][ext]['prog_name'] =  'Windows CMD.exe'
          conf['default']['extensions'][ext]['prog_path'] =  'C:\windows\system32\cmd.exe'
          conf['default']['extensions'][ext]['prog_args'] =  '/C'
        end


        File.open(filename, 'w+') {|f| f.write(conf.to_yaml) }
        puts "Profiles have been saved in #{filename}\nYou can either modify such file directly. Enjoy!"

      else
        until correct

          finished = false

          until finished

            puts "\n######### [" + " Profiles configuration ".red + "] #########"

            puts "Please insert the unique name for this profile"
            pname = gets.chop

            conf[pname] = {}
            conf[pname]['OS'] = {}
            conf[pname]['screenshots'] = {}
            conf[pname]['extensions'] = {}

            puts "Please insert the information on the OS you want to associate with this profile. This info must reflect the one inserted into the sandboxes.yml file"
            puts "OS Type (Windows|Linux) [Windows] "
            conf[pname]["OS"]['type'] = (t = gets.chop).empty? ? 'Windows' : t
            puts "OS Version: (e.g. XP SP3) [XP SP3]"
            conf[pname]["OS"]['version'] = (t = gets.chop).empty? ? 'XP SP3' : t
            puts "OS Language:  [eng]"
            conf[pname]["OS"]['lang'] = (t = gets.chop).empty? ? 'eng' : t

            puts "Sandbox parameters"
            puts "Insert the time (seconds) that the Sandbox should be run before it's reverted [60]"
            conf[pname]["sleeptime"] = (t = gets.chop).empty? ? 60 : t

            puts "Insert how many screenshots do you want to take [1]"
            conf[pname]['screenshots']["number"] = (t = gets.chop).empty? ? 1 : t.to_i

            if conf[pname]["num_screenshots"] > 1
              puts "Insert the time interval (seconds) between each screenshot [5] "
              conf[pname]["screenshots"]['delay_inbetween'] = (t = gets.chop).empty? ? 5 : t.to_i
            end

            puts "After how many seconds do you want to take the first screenshot? [1]"
            conf[pname]["screenshots"]['delay_first'] = (t = gets.chop).empty? ? 1 : t.to_i


            puts "Enable Virus Total queries? VT API key must be in .dorothy.yml [y]"
            t = gets.chop
            (t.empty? || t == "y" || t == "yes") ? conf[pname]["vtotal_query"] = true : conf[pname]["vtotal_query"] = false

            puts "Adding basic extensions (exe, bat, html, rtf)"

            %w(exe bat html rtf).each do |ext|
              conf[pname]['extensions'][ext] = Hash.new
              conf[pname]['extensions'][ext]['prog_name'] =  'Windows CMD.exe'
              conf[pname]['extensions'][ext]['prog_name'] =  'C:\windows\system32\cmd.exe'
              conf[pname]['extensions'][ext]['prog_name'] =  '/C'
            end

            puts "Profiles configured. Want you to configure another one? [n]"
            t = gets.chop

            if t == "y" || t == "yes"
              finished = false
            else
              finished = true
            end

          end

          puts "Configuration finished"
          puts "Confirm? [y]"
          t = gets.chop
          puts t

          if t.empty? || t == "y" || t == "yes"
            File.open(filename, 'w+') {|f| f.write(conf.to_yaml) }
            correct = true
            puts "Profiles have been saved in #{filename}\nYou can either modify such file directly. Enjoy!"
          else
            puts "Please reinsert the info"
            correct = false
          end
        end
      end
    end




    #Creates the sandbox configuration file
    def create_sandbox(sboxfile)

      correct = false

      until correct

        conf = Hash.new

        finished = false

        until finished
          puts "Please insert a unique name for your Sandbox (Must be the same name of the one it has in the ESX library) e.g. WinXP1"
          name = gets.chop
          conf[name] = Hash.new

          puts "Please insert the type of the sandbox (virtual|phisical|mobile-virtual|external) [virtual]"
          conf[name]["type"] = (t = gets.chop).empty? ? "virtual" : t
          puts ">" + conf[name]["type"]

          puts "Please insert the OS name [Windows]"
          conf[name]["os"] = (t = gets.chop).empty? ? "Windows" : t
          puts ">" + conf[name]["os"]

          puts "Please insert the OS version [XP SP2]"
          conf[name]["version"] = (t = gets.chop).empty? ? "XP SP2" : t
          puts ">" + conf[name]["version"]

          puts "Please insert the OS language [eng]"
          conf[name]["os_lang"] = (t = gets.chop).empty? ? "eng" : t
          puts ">" + conf[name]["os_lang"]

          puts "Please insert the Sandbox ipaddress"
          conf[name]["ipaddress"] = gets.chop
          puts ">" + conf[name]["ipaddress"]


          puts "Please insert the Sandbox username [administrator]"
          conf[name]["username"] = (t = gets.chop).empty? ? "administrator" : t
          puts ">" + conf[name]["username"]

          puts "Please insert the Sandbox password"
          conf[name]["password"] = gets.chop
          puts ">" + conf[name]["password"]

          puts "Sandbox configured. Want you to configure another one? [n]"
          t = gets.chop

          if t == "y" || t == "yes"
            finished = false
          else
            finished = true
          end


        end

        puts "Configuration finished"
        puts "Confirm? [y]"
        t = gets.chop
        puts t

        if t.empty? || t == "y" || t == "yes"
          File.open(sboxfile, 'w+') {|f| f.write(conf.to_yaml) }
          correct = true
          puts "Configuration file has been saved in #{sboxfile}\nYou can either modify such file directly. Enjoy!"
        else
          puts "Please reinsert the info"
          correct = false
        end

      end
    end



    #Creates the Source configuration file
    def create_sources(sourcesfile = DoroSettings.env[:home] + '/etc/sources.yml')

      correct = false

      until correct

        conf = Hash.new

        #Add WGUI as default source

        conf['webgui'] = Hash.new
        conf['webgui']["type"] = 'web'
        conf['webgui']["typeid"] = 1
        conf['webgui']["localdir"] =  DoroSettings.env[:home] + '/opt/bins/webgui'
        conf['webgui']["priority"] = 3
        conf['webgui']["profile"]  = 'default'

        finished = false

        until finished
          puts "Please insert a unique name for the binary source you want to add"
          sname = gets.chop

          conf[sname] = Hash.new

          puts "Please specify the binary source type (system|ssh|mail) [system]"
          conf[sname]["type"] = (t = gets.chop).empty? ? "system" : t
          puts ">" + conf[sname]["type"]

          case conf[sname]["type"]
            when "system" then
              puts "Please specify the system folder where are located the binaries [#{DoroSettings.env[:home]}/opt/bins/#{sname}]"
              conf[sname]["localdir"] = (t = gets.chop).empty? ? "#{DoroSettings.env[:home]}/opt/bins/#{sname}" : t
            when "mail" then
              puts "Please specify the IP address/hostname of the mail server (e.g. pop-mail.outlook.com)"
              conf[sname]["address"] = gets.chop

              puts "Please specify the username used for the authentication"
              conf[sname]["username"] = gets.chop

              puts "Please specify the password used for the authentication"
              conf[sname]["password"] = gets.chop

              puts "Please specify the TCP port used by the mailserver [993]"
              conf[sname]["port"] = (t = gets.chop).empty? ? 993 : t.to_i
              puts ">" + conf[sname]["port"].to_s

              puts "Is SSL required for this mailbox (true|false)? [true]"
              t = (gets.chop == "false" ? false : true)
              conf[sname]["enable_ssl"] = t
              puts ">" + conf[sname]["enable_ssl"].to_s

              puts "How many emails do you want to retreive during every request? [3]"
              conf[sname]["n_emails"] = (t = gets.chop).empty? ? 3 : t.to_i
              puts ">" + conf[sname]["n_emails"].to_s

              puts "Do you want to delete the emails from the server once downloaded? [true] (Warning, if false, Dorothy wont understand which email is new. Put false only for development/testing)"
              t = (gets.chop == "false" ? false : true)
              conf[sname]["delete_once_downloaded"] = t
              puts ">" + conf[sname]["delete_once_downloaded"].to_s

              puts "Please specify the system folder where the attachments will be temporaly copied into [#{DoroSettings.env[:home]}/opt/bins/#{sname}]"
              conf[sname]["localdir"] = (t = gets.chop).empty? ? "#{DoroSettings.env[:home]}/opt/bins/#{sname}" : t

            when "ssh" then
              puts "Please specify the IP address/hostname of the remote server"
              conf[sname]["host"] = gets.chop

              puts "Please specify the ssh TCP port of the remote server [22]"
              conf[sname]["port"] = (t = gets.chop).empty? ? 22 : t.to_i
              puts ">" + conf[sname]["port"].to_s

              puts "Please specify the username used for the authentication"
              conf[sname]["username"] = gets.chop

              puts "Please specify the password used for the authentication"
              conf[sname]["password"] = gets.chop

              puts "Please specify the remote path where the binaries are"
              conf[sname]["remotedir"] = gets.chop

              puts "Please specify the system folder where the binaries will be temporaly copied into [#{DoroSettings.env[:home]}/opt/bins/#{sname}]"
              conf[sname]["localdir"] = (t = gets.chop).empty? ? "#{DoroSettings.env[:home]}/opt/bins/#{sname}" : t
          end


          puts "Please specify the priority of this source. 1 is the lowest [1]"
          conf[sname]["priority"] = (t = gets.chop).empty? ? 1 : t.to_i
          puts ">" + conf[sname]["priority"].to_s

          puts "Please specify which analysis profile you want to associate with this source. [default]"
          conf[sname]["profile"] = (t = gets.chop).empty? ? "default" : t
          puts ">" + conf[sname]["profile"]


          puts "Binary source added. Do you want to add another one? [n]"
          t = gets.chop

          if t == "y" || t == "yes"
            finished = false
          else
            finished = true
          end


        end

        puts "Configuration finished"
        puts "Confirm? [y]"
        t = gets.chop
        puts t

        if t.empty? || t == "y" || t == "yes"
          File.open(sourcesfile, 'w+') {|f| f.write(conf.to_yaml) }
          correct = true
          puts "Configuration file has been saved in #{sourcesfile}\nYou can either modify such file directly. Enjoy!"
        else
          puts "Please reinsert the info"
          correct = false
        end

      end
    end



    #This method will populate the dorothive table sandboxes
    def init_sandbox(file="../etc/sandboxes.yml")
      conf = YAML.load_file(file)

      db = Insertdb.new
      db.begin_t

      LOGGER.warn "INIT", "Warning, the SandBox table is gonna be flushed, and updated with the new file"
      db.flush_table("sandboxes")

      conf.each_key do |sbox|
        LOGGER.info "INIT", "Inserting #{sbox}"
        values = conf[sbox].values_at("type", "os", "version", "os_lang", "ipaddress", "username", "password")
        values.insert(0, "default")
        values.insert(1, sbox)
        values.push("default")

        unless db.insert("sandboxes", values)             #no it isn't, insert it
          LOGGER.fatal "INIT", " ERROR-DB, please redo the operation"
          db.rollback
          next
        end
      end

      db.commit
      db.close
      LOGGER.info "INIT", "Sandboxes correctly inserted into the database"

    end
  end
end
