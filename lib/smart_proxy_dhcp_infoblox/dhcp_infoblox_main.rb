# encoding: utf-8
require 'dhcp_common/server'
require 'infoblox'
require 'ipaddr'

module Proxy::DHCP::Infoblox
  class Provider < ::Proxy::DHCP::Server
    include Proxy::Log
    include Proxy::Util

    attr_reader :infoblox_user, :infoblox_pw, :server

    def initialize
      super(Proxy::DhcpPlugin.settings.server)

      server        = Proxy::DhcpPlugin.settings.server
      infoblox_user = Proxy::DHCP::Infoblox::Plugin.settings.infoblox_user
      infoblox_pw   = Proxy::DHCP::Infoblox::Plugin.settings.infoblox_pw
      @record_type  = Proxy::DHCP::Infoblox::Plugin.settings.record_type
      @delete_host  = Proxy::DHCP::Infoblox::Plugin.settings.delete_host
      wapi_version  = Proxy::DHCP::Infoblox::Plugin.settings.wapi_version

      ::Infoblox.wapi_version = wapi_version.to_s
      @connection = ::Infoblox::Connection.new(username: infoblox_user, password: infoblox_pw, host: server)
      @grid = ::Infoblox::Grid.get(@connection).first

      logger.debug "Loaded infoblox provider with #{@record_type} record_type and #{wapi_version} wapi_version"
    end

    def initialize_for_testing(params)
      @name = params[:name] || @name
      @service = params[:service] || service
      @dhcp_server = params[:dhcp_server] || @dhcp_server
      @username = params[:username] || @username
      @password = params[:password] || @password
      @record_type = params[:record_type] || @record_type
      @wapi_version = params[:wapi_version] || @wapi_version
      self
    end

    def load_subnets
      logger.debug 'load_subnets'
      ::Infoblox::Network.all(@connection).each do |obj|
        next unless match = obj.network.split('/')
        tmp = IPAddr.new(obj.network)
        netmask = IPAddr.new(tmp.instance_variable_get('@mask_addr'), Socket::AF_INET).to_s
        next unless managed_subnet? "#{match[0]}/#{netmask}"
        options = {}
        service.add_subnets(Proxy::DHCP::Subnet.new(match[0], netmask, options))
      end
    end

    def find_subnet(network_address)
      # returns Proxy::DHCP::Subnet that has network_address or nil if none was found
      # network = ::Infoblox::Ipv4address.find(connection, "ip_address" => network_address).first.network
      super
    end

    def load_subnet_data(subnet)
      # intentionally do nothing
    end

    def load_infoblox_subnet_data(subnet)
      # Load network from infoblox, iterate over ips to gather additional settings
      logger.debug 'load_infoblox_subnet_data'

      if @record_type == 'host'
        network = ::Infoblox::Ipv4address.find(@connection, 'network' => "#{subnet.network}/#{subnet.cidr}", 'status' => 'USED', 'usage' => 'DHCP', '_max_results' => 2**(32 - subnet.cidr))

        # Find out which hosts are in use
        network.each do |host|
          # next if certain values are not set
          next if host.names.empty? || host.mac_address.empty? || host.ip_address.empty?
          hostdhcp = ::Infoblox::HostIpv4addr.find(@connection, 'ipv4addr' => host.ip_address).first
          next unless hostdhcp.configure_for_dhcp

          opts              = { hostname: host.names.first }
          opts[:mac]        = host.mac_address
          opts[:ip]         = host.ip_address
          opts[:nextServer] = hostdhcp.nextserver unless hostdhcp.use_nextserver
          opts[:filename]   = hostdhcp.bootfile unless hostdhcp.use_bootfile

          # broadcast and network entrys are not deleteable
          opts[:deleteable] = true unless (host.types & %w(BROADCAST NETWORK)).any?

          service.add_host(subnet.network, Proxy::DHCP::Reservation.new(opts.merge(subnet: subnet)))
        end
      elsif @record_type == 'fixed_address'
        network = ::Infoblox::Fixedaddress.find(@connection, 'network' => "#{subnet.network}/#{subnet.cidr}", '_max_results' => 2**(32 - subnet.cidr))

        network.each do |host|
          logger.debug "Processing host: #{host.name} #{host.mac} #{host.ipv4addr}"

          next if host.name.nil? || host.mac.nil? || host.ipv4addr.nil?

          opts        = { hostname: host.name }
          opts[:mac]  = host.mac
          opts[:ip]   = host.ipv4addr

          service.add_host(subnet.network, Proxy::DHCP::Reservation.new(opts.merge(subnet: subnet)))
        end
      end
    end

    def all_hosts(network_address)
      # returns all reservations in a subnet with network_address
      logger.debug "infoblox.all_hosts #{network_address}"
      load_infoblox_subnet_data(find_subnet(network_address))
      super
    end

    def unused_ip(network_address, mac_address, from_ip_address, to_ip_address)
      # returns first available ip address in a subnet with network_address, for a host with mac_address, in the range of ip addresses: from_ip_address, to_ip_address

      logger.debug "Infoblox unused_ip Network_address: #{network_address} #{mac_address}, #{from_ip_address}, #{to_ip_address}"

      if from_ip_address.empty? && to_ip_address.empty?
        logger.debug 'no range specified in foreman - getting next available ip for network'

        ::Infoblox::Network.find(@connection, network: "#{network_address.network}/#{network_address.cidr}").first.next_available_ip(1, excluded_addresses)
      else
        logger.debug 'getting next free ip using range'

        found_range = ::Infoblox::Range.find(@connection, network: "#{network_address.network}/#{network_address.cidr}").find { |range| range.start_addr == from_ip_address && range.end_addr == to_ip_address }
        raise Proxy::DHCP::Error, 'failed to find range in infoblox' if found_range.nil?

        validate_ip found_range.next_available_ip.first
      end
    end

    def find_record(_subnet_address, an_address)
      logger.debug 'find_record'

      # record can be either ip or mac, true = mac --> lookup ip
      if an_address.is_a?(String) && valid_mac?(an_address)
        if @record_type == 'host'
          hostdhcp = ::Infoblox::HostIpv4addr.find(@connection, 'mac' => an_address)
        elsif @record_type == 'fixed_address'
          hostdhcp = ::Infoblox::Fixedaddress.find(@connection, 'mac' => an_address)
        end

        return nil if hostdhcp.empty?
        ipv4address = hostdhcp.first.ipv4addr
      elsif an_address.is_a?(String)
        validate_ip an_address
        ipv4address = an_address
      end

      if @record_type == 'host'
        host = ::Infoblox::Host.find(@connection, 'ipv4addr' => ipv4address)
        return nil if host.empty? || host.first.name.empty?

        hostdhcp = ::Infoblox::HostIpv4addr.find(@connection, 'ipv4addr' => ipv4address).first
        return nil unless hostdhcp.configure_for_dhcp
        return nil if hostdhcp.mac.empty? || hostdhcp.ipv4addr.empty?

        opts              = { hostname: host.first.name }
        opts[:mac]        = hostdhcp.mac
        opts[:ip]         = hostdhcp.ipv4addr
        opts[:deleteable] = true
        opts[:nextServer] = hostdhcp.nextserver if hostdhcp.use_nextserver
        opts[:filename]   = hostdhcp.bootfile if hostdhcp.use_bootfile
      elsif @record_type == 'fixed_address'
        logger.debug "find_record for #{an_address}"
        fixed_address = ::Infoblox::Fixedaddress.find(@connection, 'ipv4addr' => ipv4address)
        return nil if fixed_address.nil? || fixed_address.empty?

        opts              = { hostname: fixed_address.first.name }
        opts[:deleteable] = true
        opts[:mac]        = fixed_address.first.mac
        opts[:ip]         = fixed_address.first.ipv4addr
      end

      # Subnet should only be one, not checking that yet
      subnet = subnets.find { |s| s.include? ipv4address }
      Proxy::DHCP::Record.new(opts.merge(subnet: subnet))
    end

    def create_infoblox_host_record(record)
      logger.debug 'create_infoblox_host_record'
      host = ::Infoblox::Host.new(connection: @connection)
      host.name = record.name
      host.add_ipv4addr(record.ip)
      host.post
    end

    def create_infoblox_fixed_address(record)
      logger.debug 'create_infoblox_fixed_address'

      fixed_address           = ::Infoblox::Fixedaddress.new(connection: @connection)
      fixed_address.name      = record.name
      fixed_address.ipv4addr  = record.ip
      fixed_address.mac       = record.mac

      fixed_address.post
    end

    def restart_grid
      # restart the grid to make the DHCP settings take effect.
      # for unkown reasons this can fail if it gets executed to quick
      # after a host has been added to the infoblox appliance.
      # we try three times and sleep in between, which is kind of a
      # hacky fix, but it works
      logger.debug 'restarting grid...'

      1.upto(3) do |tries|
        sleep tries
        begin
          @grid.restartservices
          logger.debug 'Restarted grid.'
          return
        rescue Exception
          logger.debug "Retrying DHCP restart. Try ##{tries}..."
        end
      end

      logger.info 'Restarting Grid failed.'
    end

    def add_record(options = {})
      logger.debug 'Add Record'
      record = super

      # Since we support 2 types of records, do the right thing with each one.
      if @record_type == 'host'
        host = ::Infoblox::Host.find(@connection, 'ipv4addr' => record.ip)
        # If empty create:
        create_infoblox_host_record(record) if host.empty?

        host = ::Infoblox::Host.find(@connection, 'ipv4addr' => record.ip).first
        options = record.options
        # Overwrite values without checking
        # Select correct ipv4addr object from ipv4addrs array
        hostip = host.ipv4addrs.find { |ip| ip.ipv4addr == record.ip }
        logger.debug "Add Record - record.name: #{record.name}, hostip.host #{hostip.host}, record.mac #{record.mac}, record.ip #{record.ip}"
        logger.debug "Add Record - options[:nextServer] #{options[:nextServer]}, options[:filename] #{options[:filename]}, hostip.ipv4addr: #{hostip.ipv4addr} "
        raise InvalidRecord, "#{record} Hostname mismatch" unless hostip.host == record.name

        hostip.mac                = record.mac
        hostip.configure_for_dhcp = true
        hostip.nextserver         = options[:nextServer]
        hostip.use_nextserver     = true
        hostip.bootfile           = options[:filename]
        hostip.use_bootfile       = true

        ## Test if Host Entry has correct IP
        raise InvalidRecord, "#{record} IP mismatch" unless hostip.ipv4addr == record.ip

        # Send object
        host.put
        # restart grid for the changes to take effect
        restart_grid
        record
      elsif @record_type == 'fixed_address'
        create_infoblox_fixed_address(record)
        record
      end
    end

    def del_record(subnet, record)
      validate_subnet subnet
      validate_record record

      logger.debug "deleting record #{record} with subnet #{subnet}"
      # return nil if fixed_address.emtpy? || fixed_address.first.name.empty?
      # return nil if fixed_address.emtpy?

      # TODO: Refactor this into the base class
      raise InvalidRecord, "#{record} is static - unable to delete" unless record.deleteable?

      if @record_type == 'host'
        host = ::Infoblox::Host.find(@connection, 'ipv4addr' => record.ip)
        unless host.empty?
          # if not empty, first element is what we want to edit
          host = host.first
          # Select correct ipv4addr object from ipv4addrs array
          hostip = host.ipv4addrs.find { |ip| ip.ipv4addr == record.ip }

          if @delete_host
            # delete whole host if there are no ip addresses for it
            # if this is enabled in the configuration
            host.ipv4addrs.delete hostip
            if host.ipv4addrs.empty?
              logger.debug 'deleting whole host'
              host.delete
            else
              logger.debug 'removing ip from host'
              host.put
            end
          else
            # else set dhcp inactive
            logger.debug 'setting dhcp inactive for host'
            hostip.configure_for_dhcp = false
            host.put
          end
        end
      elsif @record_type == 'fixed_address'
        # Delete the fixed address record.
        fixed_address = ::Infoblox::Fixedaddress.find(@connection, 'ipv4addr' => record.ip).first
        fixed_address.delete
      end
    end
  end
end
