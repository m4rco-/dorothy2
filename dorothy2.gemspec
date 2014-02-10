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
  gem.required_ruby_version = '>= 1.9.3'
  gem.add_dependency(%q<net-scp>, [">= 1.0.4"])
  gem.add_dependency(%q<net-ssh>, [">= 2.2.1"])
  gem.add_dependency(%q<trollop>, [">= 1.16.2"])
  gem.add_dependency(%q<rest-client>, [">= 1.6.1"])
  gem.add_dependency(%q<mime-types>, [">= 1.16"])
  gem.add_dependency(%q<colored>, [">= 1.2"])
  gem.add_dependency(%q<ruby-pg>, [">= 0.7.9.2008.01.28"])
  gem.add_dependency(%q<virustotal>, [">= 2.0.0"])
  gem.add_dependency(%q<nokogiri>, ["~> 1.5.10"])
  gem.add_dependency(%q<rbvmomi>, ["~> 1.6.0"])
  gem.add_dependency(%q<ruby-filemagic>, [">= 0.4.2"])
  #for dparser
  gem.add_dependency(%q<net-dns>, [">= 0.8.0"])
  gem.add_dependency(%q<geoip>, [">= 1.2.1"])
  gem.add_dependency(%q<tmail>, [">= 1.2.7.1"])
  gem.post_install_message = '\n WARING: If you are upgrating from a previous version, read the UPDATE file!\n'
end

