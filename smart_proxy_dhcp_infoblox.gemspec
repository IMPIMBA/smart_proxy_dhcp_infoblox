# encoding: utf-8
require File.expand_path('../lib/smart_proxy_dhcp_infoblox/dhcp_infoblox_version', __FILE__)
require 'date'

Gem::Specification.new do |s|
  s.name        = 'smart_proxy_dhcp_infoblox'
  s.version     = Proxy::DHCP::Infoblox::VERSION
  s.date        = Date.today.to_s
  s.license     = 'GPLv3'
  s.authors     = ['Klaas Demter']
  s.email       = ['demter@atix.de']
  s.homepage    = 'https://github.com/theforeman/smart_proxy_dhcp_infoblox'

  s.summary     = "Infoblox DHCP provider plugin for Foreman's smart proxy"
  s.description = "Infoblox DHCP provider plugin for Foreman's smart proxy"

  s.files       = Dir['{config,lib,bundler.d}/**/*'] + ['README.md', 'LICENSE']
  s.test_files  = Dir['test/**/*']

  s.add_development_dependency('rake')
  s.add_development_dependency('mocha')
  s.add_development_dependency('test-unit')
end
