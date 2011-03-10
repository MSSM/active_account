module ActiveAccount
  module Ldap
 
    def connect(login, password)
      @config[:servers].each do |server|
        @current_connection = Net::LDAP.new(
          :host       => server,
          :port       => @config[:port],
          :base       => @config[:base],
          :encryption => @config[:encryption],
          :auth       => {:method => :simple, :username => login, :password => password}
        )
        return true if connected?
      end
    end

    def connect_as_admin
      connect(@config[:username], @config[:password])
    end

    def connected?
      begin
        return true if @current_connection.bind
      rescue
        return false
      end
    end

    private

    def ldap_execute(method, *args, &block)
      Rails.logger.info "#{method}(#{args.inspect})"
      ms = [Benchmark.ms { @current_connection.send(method, *args, &block) }, 0.01].max
      result = @current_connection.get_operation_result
      log_message = 'Ldap completed in %.0fms' % ms
      log_message << " (#{result.inspect})"
      Rails.logger.info log_message
      return result
    end
 

    ####################
    # Get and parse objectclasses from the RootDSE
 
    def load_available_attributes
      get_objectclasses.each do |objectclass|
        parsed = Hash.new
        parse_attributes(objectclass, parsed)
        if @user.objectclass.map { |o| o.downcase }.include? parsed['NAME'].first.downcase
          @objectclasses << parsed
        end
      end
      @objectclasses.each do |oc|
        @available_attributes = @available_attributes + oc['MAY']  unless oc['MAY'].nil?
        @available_attributes = @available_attributes + oc['MUST'] unless oc['MUST'].nil?
      end
      @available_attributes.map! { |a| a.downcase }
    end

    # TODO: Refactor
    def get_objectclasses
      connect_as_admin
      filter = Net::LDAP::Filter.construct("objectclass=*")
      @current_connection.search(
        :filter     => filter,
        :scope      => Net::LDAP::SearchScope_BaseObject,
        :attributes => ['objectclasses'],
        :base       => @current_connection.search(
                         :base   => "",
                         :filter => filter,
                         :scope  => Net::LDAP::SearchScope_BaseObject
                       ).first.subschemasubentry.first
      ).first.objectclasses
    end

    # Borrowed from active_ldap/schema.rb :)
    # from RFC 2252
    attribute_type_description_reserved_names =
      ["NAME", "DESC", "OBSOLETE", "SUP", "EQUALITY", "ORDERING", "SUBSTR",
       "SYNTAX", "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "USAGE"]
    syntax_description_reserved_names = ["DESC"]
    object_class_description_reserved_names =
      ["NAME", "DESC", "OBSOLETE", "SUP", "ABSTRACT", "STRUCTURAL",
       "AUXILIARY", "MUST", "MAY"]
    matching_rule_description_reserved_names =
      ["NAME", "DESC", "OBSOLETE", "SYNTAX"]
    matching_rule_use_description_reserved_names =
      ["NAME", "DESC", "OBSOLETE", "APPLIES"]
    private_experiment_reserved_names = ["X-[A-Z\\-_]+"]
    reserved_names =
      (attribute_type_description_reserved_names +
       syntax_description_reserved_names +
       object_class_description_reserved_names +
       matching_rule_description_reserved_names +
       matching_rule_use_description_reserved_names +
       private_experiment_reserved_names).uniq
    RESERVED_NAMES_RE = /(?:#{reserved_names.join('|')})/

    def parse_attributes(str, attributes)
      str.scan(/([A-Z\-_]+)\s+
                (?:\(\s*(\w[\w\-;]*(?:\s+\$\s+\w[\w\-;]*)*)\s*\)|
                   \(\s*([^\)]*)\s*\)|
                   '([^\']*)'|
                   ((?!#{RESERVED_NAMES_RE})[a-zA-Z][a-zA-Z\d\-;]*)|
                   (\d[\d\.\{\}]+)|
                   ()
                )/x
               ) do |name, multi_amp, multi, string, literal, syntax, no_value|
        case
        when multi_amp
          values = multi_amp.rstrip.split(/\s*\$\s*/)
        when multi
          values = multi.scan(/\s*'([^\']*)'\s*/).collect {|value| value[0]}
        when string
          values = [string]
        when literal
          values = [literal]
        when syntax
          values = [syntax]
        when no_value
          values = ["TRUE"]
        end

        attributes[normalize_attribute_name(name)] ||= []
        attributes[normalize_attribute_name(name)].concat(values)
      end
    end

    def normalize_attribute_name(name)
      name.upcase.gsub(/_/, "-")
    end
  end
end
