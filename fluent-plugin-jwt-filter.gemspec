# coding: utf-8

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'fluent-plugin-jwt-filter'
  spec.version       = '0.1.1'
  spec.authors       = ['Toyokazu Akiyama', 'Serge Tkatchouk']
  spec.email         = ['toyokazu@gmail.com', 'sp1j3t@gmail.com']

  spec.summary       = 'Fluent JSON Web Token Filter plugin'
  spec.description   = 'Fluent Filter plugin for (un)packing messages using JSON Web Token technology, based on the "jwt" library'
  spec.homepage      = 'https://github.com/spijet/fluent-plugin-jwt-filter'
  spec.license       = 'Apache License Version 2.0'

  spec.files         = `git ls-files`.gsub(%r{images\/[\w\.]+\n}, '').split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.3.0'

  spec.add_dependency 'fluentd', '~> 0.14.0'
  spec.add_runtime_dependency 'jwt', '>= 2.1.0'

  spec.add_development_dependency 'bundler', '~> 1.14'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'test-unit'
end
