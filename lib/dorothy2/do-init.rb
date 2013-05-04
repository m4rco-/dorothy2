module Dorothy

  module DoroConfig

    extend self

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

        #################################################
        ###SANDBOX
        ################################################

        puts "Sandbox configuration settings"
        puts "Insert the time (seconds) that the Sandbox should be run before it's reverted [60]"
        conf["sandbox"]["sleeptime"] = (t = gets.chop).empty? ? 60 : t

        puts "Insert the time (seconds) when Dorothy should take the first screenshot [1]"
        conf["sandbox"]["screen1time"] = (t = gets.chop).empty? ? 1 : t

        puts "Insert the time (seconds) when Dorothy should take the first screenshot [15]"
        conf["sandbox"]["screen2time"] = (t = gets.chop).empty? ? 15 : t



        ################################################
        ###DOROTHY ENVIRONMENT
        ################################################

        puts "Dorothy Environment settings"

        home = File.expand_path("..",Dir.pwd)
        puts "The Dorothy home directory is #{home}"

        conf["env"]["home"] = home
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

        puts "Please insert the Dorothive (Dorothy DB) information"

        puts "DB hostname/IP address [localhost]:"
        conf["dorothive"]["dbhost"] = (t = gets.chop).empty? ? "localhost" : t

        puts "DB Name [dorothive]:"
        conf["dorothive"]["dbname"] = (t = gets.chop).empty? ? "dorothive" : t

        puts "DB Username [dorothy]:"
        conf["dorothive"]["dbuser"] = (t = gets.chop).empty? ? "dorothy" : t

        puts "DB Password"
        conf["dorothive"]["dbpass"] = gets.chop

        conf["dorothive"]["ddl"] = "#{home}/etc/ddl/dorothive.ddl"


        ######################################################
        ###ESX
        ######################################################

        puts "Please insert the IP address of your ESX server"
        conf["esx"]["server"] = gets.chop

        puts "Please insert the ESX username"
        conf["esx"]["host"] = gets.chop

        puts "Please insert the ESX password"
        conf["esx"]["pass"] = gets.chop

        #puts "Sandbox Configuration"               #TODO -> insertdb



        ######################################################
        ###NAM
        ######################################################

        puts "Network Analysis Module (NAM) configuration"
        puts "Please insert the information of the host that you will use for sniffing the Sandbox traffic"
        puts "IP Addres:"
        conf["nam"]["host"] = gets.chop
        puts "Username [dorothy] :"
        conf["nam"]["port"] = (t = gets.chop).empty? ? "22" : t
        puts "Password:"
        conf["nam"]["pass"] = gets.chop
        puts "Folder where to store PCAP files [~/pcaps]"
        conf["nam"]["pcaphome"] = (t = gets.chop).empty? ? "~/pcaps" : t


        ######################################################
        ###VIRUS TOTAL
        ######################################################

        puts "In order to retrieve Virus signatures, Dorothy needs to contact VirusTotal, please enter your VT API key here, if you don't have one yet, go here: "
        conf["virustotal"]["vtapikey"] = gets.chop

        puts "Configuration finished"
        puts "Confirm? [y]"

        t = gets.chop
        if t.empty? || t == "y" || t == "yes"
          File.open("#{home}/etc/dorothy.yml", 'w+') {|f| f.write(conf.to_yaml) }
          correct = true
          puts "Configuration file has been saved in #{home}/etc/dorothy.conf\nYou can either modify such file directly. Enjoy!"
        else
          puts "Please reinsert the info"
          correct = false
        end

      end

    end

    def create_sandbox

      correct = false

      until correct

        conf = Hash.new

        finished = false

        until finished
          puts "Please insert a unique name for your Sandbox - e.g. WinXP1"
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
          home = File.expand_path("..",Dir.pwd)
          File.open("#{home}/etc/sandboxes.yml", 'w+') {|f| f.write(conf.to_yaml) }
          correct = true
          puts "Configuration file has been saved in #{home}/etc/sandboxes.yml\nYou can either modify such file directly. Enjoy!"
        else
          puts "Please reinsert the info"
          correct = false
        end

      end
    end



    #This method will populate the dorothive table sandboxes
    def init_sandbox(file="../etc/sandboxes.yml")
      conf = YAML.load_file(file)
      conf.each_key do |sbox|
        LOGGER.info "INIT", "Inserting #{sbox}"
        values = conf[sbox].values_at("type", "os", "version", "os_lang", "ipaddress", "username", "password")
        values.insert(0, "default")
        values.insert(1, sbox)
        values.push("default")

        db = Insertdb.new
        db.begin_t

        if !db.insert("sandboxes", values)             #no it isn't, insert it
          LOGGER.fatal "BFM", " ERROR-DB, please redo the operation"
          db.rollback
          next
        else
          db.commit
          db.close
          LOGGER.info "INIT", "Sandboxes correctly inserted into the database"
        end

      end
    end
  end
end
