# Dorothy2

A malware/botnet analysis framework written in Ruby.


##Requirements

>WARNING:
The current version of Dorothy, is based on VMWare ESX5. ESXi is not supported due to its limitations in using the
VMWare API.
However, the overall framework could be easily customized in order to use another virtualization engine. Dorothy2 is
very modular,and any customization or modification is very welcome.

Dorothy needs the following software (not expressly in the same host) in order to be executed:

* VMWare ESX >= 5.0  (tip: if you download ESXi, you can evaluate ESX for 30 days)
* Ruby 1.8.7
* Postgres >= 9.0
* At least one Windows virtual machine
* One unix-like machine dedicated to the Network Analysis Engine(NAM) (tcpdump/ssh needed)
* [pcapr-local](https://github.com/mudynamics/pcapr-local )  (only used by doroParser)
* MaxMind libraries (only used by doroParser)


## Installation

It is raccommended to follow this step2step process:

1. Set your ESX environment
2. Install the required software
3. Install Dorothy and libmagic libraries
4. Start Dorothy, and configure it
5. Use Dorothy

### 1. Set your ESX environment
1. Basic configuration (ssh)
 * From vSphere:

            Configuration->Security Profile->Services->Proprieties->SSH->Options->Start and Stop with host->Start->OK

2. Configure the Windows VMs used for sandboxing
 * Create a test_ping.bat file into C:\ folder, with the following content:

            ping -n 1 google.com
>This file will be used for checking if the VM has internet access. You can substitute "google.com" with whatever host you like. Just a suggestion: use hostnames instead of IP addresses. The aim of this test doesn't care if the DNS is not resolving, or the IP addresses is unreachable. It cares only if *everything* works.

 * Disable Windows firewall (preferred)
 * VMWare Tools must be installed in the Guest system.
3. Configure the unix VM used by the NAM
     * Install tcpdump and sudo

                #apt-get install tcpdump sudo

     * Create a dedicated user for dorothy (e.g. "dorothy")

                #useradd dorothy
     * Add dorothy's user permission to execute/kill tcpdump to the sudoers file:

                #visudo
                add the following line:
                dorothy  ALL = NOPASSWD: /usr/sbin/tcpdump, /bin/kill

     * Add the pubblic key of the user who will execute Dorothy in /home/dorothy/.ssh/authorized_keys

     > Consider that you are going to execute Dorothy on your machine, and that HOST2 is the NAM. In order to access
     > to NAM in an automatic mode, Dorothy needs to authenticate to HOST2's ssh service through its public key in order
     > to avoid interactive authentication.


### 2. Install the required sofware


1. Install postgres

        $sudo apt-get install postgresql-9.1
or

        http://www.postgresql.org/download/

2. Configure a dedicated postgres user for Dorothy (or use root user instead, up to you :)

3. Install the following packages

        $sudo apt-get install ruby1.8 rubygems postgresql-server-dev-9.1 libxml2-dev  libxslt1-dev libmagic-dev

>For OSX users: all the above software are available through mac ports. A tip for libmagic: use brew instead:
>
        $ brew install libmagic
        $ brew link libmagic

Add a user dedicated to dorothy (or use the root one, up to you :)

### 3. Install Dorothy gem

*Install Dorothy gem

        $ gem install dorothy2

### 4. Start Dorothy, and configure it!

0. Install MaxMind libraries
    * [GeoLiteCity](http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz)
    * [GeoLite ASN](http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz)
    * Copy GeoLiteCity.dat and GeoIPASNum.dat into Dorothy's etc/geo/ folder

1. Start Dorothy

        $ dorothy_start -v
The following message should appear

        [WARNING] It seems that the Dorothy configuration file is not present,
        please answer to the following question in order to create it now.

2. Follow the instruction to configure
    * The environment variables (db, esx server, etc)
    * The Dorothy sources (where to get new binaries)
    * The ESX Virtual machines used for the analysis

The first time you execute Dorothy, it will ask you to fill those information in order to create the required configuration files into the etc/ folder. However, you are free to modify/create such files directly - configuration example files can be found there too.

###5. Use Dorothy
1. Copy a .exe or .bat file into $yourdorothyhome/opt/bins/manual/
2. Execute dorothy with the malwarefolder source type (if you left the default one)

    $ dorothy_start -v -s malwarefolder


## Usage

	Usage:
	$./dorothy_start [options]
	where [options] are:
       --verbose, -v:   Enable verbose mode
      --infoflow, -i:   Print the analysis flow
    --source, -s <s>:   Choose a source (from the ones defined in etc/sources.yml)
        --daemon, -d:   Stay in the backround, by constantly pooling datasources
 --SandboxUpdate, -S:   Update Dorothive with the new Sandbox file
 --DorothiveInit, -D:   (RE)Install the Dorothy Database (Dorothive)
          --help, -h:   Show this message


 >Example

    ./dorothy_start -v -s malwarefolder
    ./dorothy_stop

------------------------------------------

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
