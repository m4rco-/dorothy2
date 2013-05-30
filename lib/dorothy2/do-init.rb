# Copyright (C) 2010-2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

module Dorothy

  module DoroConfig

    extend self

    def init_home(home)
      puts "INIT".yellow + " Creating Directoy structure in #{home}"
      Dir.mkdir(home)
      unless Util.exists?("#{home}/opt")
        Dir.mkdir("#{home}/opt")
        Dir.mkdir("#{home}/opt/bins")
        Dir.mkdir("#{home}/opt/analyzed")
      end
      unless Util.exists?("#{home}/etc")
        Dir.mkdir("#{home}/etc")
        Dir.mkdir("#{home}/etc/geo")
      end
      unless Util.exists?("#{home}/var")
        Dir.mkdir("#{home}/var")
        Dir.mkdir("#{home}/var/log")
      end
      puts "INIT".yellow + " Done"
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


        ################################################
        ###DOROTHY ENVIRONMENT
        ################################################

        puts "\n######### [" + " Dorothy Environment settings ".red + "] #########"

        puts "Please insert the home folder for dorothy [#{HOME}]"
        conf["env"]["home"] = (t = gets.chop).empty? ? HOME : t

        home = conf["env"]["home"]

        unless Util.exists?(home)
          self.init_home(home)
        end




        puts "The Dorothy home directory is #{home}"

        conf["env"]["pidfile"] = "#{home}/var/dorothy.pid"
        conf["env"]["pidfile_parser"] = "#{home}/var/doroParser.pid"
        conf["env"]["analysis_dir"] = "#{home}/opt/analyzed"   # TODO if doesn't exist, create it. -> Dir.mkdir("mynewdir")
        conf["env"]["geoip"] = "#{home}/etc/geo/GeoLiteCity.dat"
        conf["env"]["geoasn"] = "#{home}/etc/geo/GeoIPASNum.dat"

        conf["env"]["dtimeout"] = 3600

        conf["env"]["logfile"] = "#{home}/var/log/dorothy.log"
        conf["env"]["logfile_parser"] = "#{home}/var/log/parser.log"
        conf["env"]["loglevel"] = 0
        conf["env"]["logage"] = "weekly"

        conf["env"]["testmode"] = true



        ######################################################
        ###DOROTHIVE
        ######################################################

        puts "\n######### [" + " Dorothive (Dorothy DB) settings ".red + "] #########"

        puts "DB hostname/IP address [localhost]:"
        conf["dorothive"]["dbhost"] = (t = gets.chop).empty? ? "localhost" : t

        puts "DB Name [dorothive]:"
        conf["dorothive"]["dbname"] = (t = gets.chop).empty? ? "dorothive" : t

        puts "DB Username [dorothy]:"
        conf["dorothive"]["dbuser"] = (t = gets.chop).empty? ? "dorothy" : t

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

        puts "Insert the time (seconds) that the Sandbox should be run before it's reverted [60]"
        conf["sandbox"]["sleeptime"] = (t = gets.chop).empty? ? 60 : t

        puts "Insert the time (seconds) when Dorothy should take the first screenshot [1]"
        conf["sandbox"]["screen1time"] = (t = gets.chop).empty? ? 1 : t

        puts "Insert the time (seconds) when Dorothy should take the second screenshot [15]"
        conf["sandbox"]["screen2time"] = (t = gets.chop).empty? ? 15 : t

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

        puts "SSH Port [22] :"
        conf["nam"]["port"] = (t = gets.chop).empty? ? 22 : t

        puts "Password:"
        conf["nam"]["pass"] = gets.chop

        puts "Folder where to store PCAP files [~/pcaps]"
        conf["nam"]["pcaphome"] = (t = gets.chop).empty? ? "~/pcaps" : t


        ######################################################
        ###VIRUS TOTAL
        ######################################################

        puts "\n######### [" + " Virus Total API ".red + "] #########"

        puts "In order to retrieve Virus signatures, Dorothy needs to contact VirusTotal,\n please enter your VT API key here, if you don't have one yet, go here (or press enter):\nhttps://www.virustotal.com/en/#dlg-join "
        conf["virustotal"]["vtapikey"] = gets.chop

        puts "\n######### [" + " Configuration finished ".yellow + "] #########"
        puts "Confirm? [y]"

        t = gets.chop
        if t.empty? || t == "y" || t == "yes"
          File.open("#{File.expand_path("~")}/.dorothy.yml", 'w+') {|f| f.write(conf.to_yaml) }
          FileUtils.ln_s("#{File.expand_path("~")}/.dorothy.yml", "#{home}/etc/dorothy.yml")
          correct = true
          puts "Configuration file has been saved in ~/.dorothy.conf and a symlink has been created in\n#{home}/etc/dorothy.yml for an easier edit. You can either modify such file directly."
          puts "\n######### [" + " Now you can restart dorothy, enjoy! ".yellow + "] #########"
        else
          puts "Please reinsert the info"
          correct = false
        end

      end

    end

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

    #This method will populate the dorothive table sandboxes
    def init_sandbox(file="../etc/sandboxes.yml")
      conf = YAML.load_file(file)

      db = Insertdb.new
      db.begin_t

      LOGGER.warn "INIT", "Waring, the SandBox table is gonna be flushed, and updated with the new file"
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
