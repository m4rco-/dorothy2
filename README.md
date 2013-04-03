# Dorothy2

A botnet analysis framework.


##Requirements

WARNING:
The current version of Dorothy, is based on VMWare ESX5. ESXi is not supported due to its limitations in using the VMWare API.
However, the overall framework could be easily customized in order to use another virtualization engine. Dorothy2 is very modular,
and any customization or modification is very welcome.


-VMWare ESX 5.0
-Ruby 1.8.7
-At least one WindowsXP virtual machine
-One unix-like machine dedicated to the Network Analysis Engine (tcpdump/ssh needed)


## Installation

Add this line to your application's Gemfile:

    gem 'dorothy2'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install dorothy2


Install libmagic :
    $ brew install libmagic
    $ brew link libmagic


VMWare Tools must be installed in the Guest system.


## Usage



------------------------------------------

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
