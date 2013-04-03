module Process
  #  Supply daemon for pre ruby 1.9
  #  Adapted from lib/active_support/core_ext/process/daemon.rb
  def self.daemon(nochdir = nil, noclose = nil)
    exit! if fork                     # Parent exits, child continues.
    Process.setsid                    # Become session leader.
    exit! if fork                     # Zap session leader. See [1].

    unless nochdir
      Dir.chdir "/"                 # Release old working directory.
    end

    unless noclose
      STDIN.reopen "/dev/null"       # Free file descriptors and
      STDOUT.reopen "/dev/null", "a" # point them somewhere sensible.
      STDERR.reopen '/dev/null', 'a'
    end

    trap("TERM") { exit }

    return 0

  end unless self.respond_to? :daemon
end


module DoroEnv

  SLEEPTIME=60	  #Malware execution time (seconds)
  SCREEN1TIME=1	  #Firt screen shot time (seconds)
  SCREEN2TIME=15	#Second screen shot time (seconds)

#ENV configuration paths
  HOME = File.expand_path(File.dirname(File.dirname(__FILE__)))
  $: << HOME

  SOURCES = {"honeypot" => {:dir => "#{HOME}/opt/bins/honeypot", :typeid=> 0}, "airis" => {:dir => "#{HOME}/opt/bins/airis", :typeid => 1}, "manual" => {:dir => "#{HOME}/opt/bins/manual", :typeid=> 2}, "honeypot2" => {:dir => "#{HOME}/opt/bins/honeypot2", :typeid=> 3}}
  PIDFILE = "#{HOME}/var/dorothy.pid"
  PIDFILE_PARSER = "#{HOME}/var/doroParser.pid"
  ANALYSIS_DIR = "#{HOME}/opt/analyzed"   # TODO if doesn't exist, create it. -> Dir.mkdir("mynewdir")

#GEOLITE FILES
  GEOIP = "#{HOME}/etc/geo/GeoLiteCity.dat"
  GEPASN = "#{HOME}/etc/geo/GeoIPASNum.dat"

#LOGGING
  LOGFILE = "#{HOME}/var/log/dorothy.log"
  LOGFILE_PARSER = "#{HOME}/var/log/parser.log"
#LOG SEVERITY LEVELS:
#  DEBUG = 0
#  INFO = 1
#  WARN = 2
#  ERROR = 3
#  FATAL = 4
#  UNKNOWN = 5
  LOGLEVEL = 0

#LOG Rotation
  LOGAGE = "weekly"



#DATABASE - Dorothive

  DBHOST = 'localhost'
  DBNAME = 'dorothive'
  DBUSER = 'postgres'
  DBPASS = 'password'

#MAM configuration properties
  ESXSERVER = '192.168.187.128'
  ESXUSER = 'root'
  ESXPASS = 'Dorothy!?!'


#GUEST configuation properties
  VMADDRESS = "192.168.187.130"
  VMUSER='billy'
  VMPASS='password'

#NSM configuration properties
  NAMSERVER = 'localhost'
  NAMUSER = 'dorothy'
  NAMPASS = 'dorothy!'
  PCAPHOME = "/Users/dorothy/pcaps"

#AIRIS

  AIRIS_URL = 'https://172.20.10.119'
  DISABLE_AIRIS_COMMENTS = true


###HONEYPOT

  HPSERVER = '46.4.208.39'
  HPUSER = 'root'
  HPPASS = '7jCg5Fq0c9'


###VIRUS TOTAL

  VTAPIKEY = "c37baad50a42d7df3f91e957255a2c6a9deabe339c2ff44d4a637fff912def48"


#TEST MODE

  TESTMODE = true

#DAEMON MODE TIMEOUT

  DTIMEOUT = 3600

end