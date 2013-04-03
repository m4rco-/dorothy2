# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dorothy2/version'

Gem::Specification.new do |gem|
  gem.name          = "dorothy2"
  gem.version       = Dorothy2::VERSION
  gem.authors       = ["marco riccardi"]
  gem.email         = ["marco.riccardi@honeynet.it"]
  gem.description   = %q{The dorothy gem}
  gem.summary       = %q{blablabla}
  gem.homepage      = "http://www.honeynet.it"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.add_dependency(%q<net-scp>, [">= 1.0.4"])
  gem.add_dependency(%q<net-ssh>, [">= 2.2.1"])
  gem.add_dependency(%q<trollop>, [">= 1.16.2"])
  gem.add_dependency(%q<rest-client>, [">= 1.6.1"])
  gem.add_dependency(%q<mime-types>, [">= 1.16"])
  gem.add_dependency(%q<colored>, [">= 1.2"])
  gem.add_dependency(%q<ruby-pg>, [">= 0.7.9.2008.01.28"])
  gem.add_dependency(%q<virustotal>, [">= 2.0.0"])
  gem.add_dependency(%q<rbvmomi>, [">= 1.3.0"])
  gem.add_dependency(%q<ruby-filemagic>, [">= 0.4.2"])

end
