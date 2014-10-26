# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dorothy2/version'

Gem::Specification.new do |gem|
  gem.name          = "dorothy2"
  gem.version       = Dorothy::VERSION
  gem.authors       = ["marco riccardi"]
  gem.email         = ["marco.riccardi@honeynet.it"]
  gem.description   = %q{A malware/botnet analysis framework written in Ruby.}
  gem.summary       = %q{More info at http://www.honeynet.it}
  gem.homepage      = "https://github.com/m4rco-/dorothy2"
  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.extra_rdoc_files = ["README.md"]
  gem.require_paths = ["lib"]
  gem.required_ruby_version = '~> 1.9.3'
  gem.add_dependency(%q<net-scp>, ["~> 1.1.2"])
  gem.add_dependency(%q<net-ssh>, ["~> 2.7.0"])
  gem.add_dependency(%q<trollop>, ["~> 2.0"])
  gem.add_dependency(%q<rest-client>, ["~> 1.6.7"])
  gem.add_dependency(%q<mail>, ["~> 2.5.4"])
  gem.add_dependency(%q<colored>, [">= 1.2"])
  gem.add_dependency(%q<pg>, [">= 0.8.0"])
  gem.add_dependency(%q<nokogiri>, ["~> 1.5.11"])
  gem.add_dependency(%q<uirusu>, ["~> 0.0.6"])
  gem.add_dependency(%q<rbvmomi>, ["~> 1.6.0"])
  gem.add_dependency(%q<ruby-filemagic>, ["~> 0.5.0"])
  gem.add_dependency(%q<activesupport>, ["~> 4.1.6"])
  gem.add_dependency(%q<activemodel>, ["~> 4.1.6"])
  gem.add_dependency(%q<activerecord>, ["~> 4.1.0.beta1"])
  gem.add_dependency(%q<sinatra>, ["~> 1.4.4"])
  gem.add_dependency(%q<sinatra-activerecord>, ["~> 1.3.0"])
  gem.add_dependency(%q<sinatra-contrib>, ["~> 1.4.2"])
  gem.add_dependency(%q<namespace>, ["~> 1.2"])
  #for dparser
  gem.add_dependency(%q<net-dns>, ["~> 0.8.0"])
  gem.add_dependency(%q<geoip>, ["~> 1.3.5"])
  gem.add_dependency(%q<whois>, ["~> 3.5.3"])
  gem.post_install_message = '\n\n\n \t\t WARING: If you are upgrating from a previous version, read the UPDATE file! \t\t\n\n\n'
end
