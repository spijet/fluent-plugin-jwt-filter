# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = "fluent-plugin-jwt-filter"
  spec.version       = "0.0.5"
  spec.authors       = ["Toyokazu Akiyama"]
  spec.email         = ["toyokazu@gmail.com"]

  spec.summary       = %q{Fluent Filter plugin for encrypting and decrypting messages using JSON Web Token technology (JSON Web Encryption, JSON Web Signature and JSON Web Key)}
  spec.description   = %q{Fluent Filter plugin for encrypting and decrypting messages using JSON Web Token technology (JSON Web Encryption, JSON Web Signature and JSON Web Key)}
  spec.homepage      = "https://github.com/toyokazu/fluent-plugin-jwt-filter"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.gsub(/images\/[\w\.]+\n/, "").split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.0.0'

  spec.add_dependency 'fluentd', '>= 0.10.0'
  spec.add_runtime_dependency("json-jwt", [">= 1.5.2"])

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"
end
