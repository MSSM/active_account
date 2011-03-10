class AccountError < StandardError
end

class EntryNotFound < AccountError
end

class ForcePasswordChange < AccountError
end

module ActiveAccount
  class Base
    def initialize(userid=nil, user=nil)
      @userid               = userid
      @current_connection   = nil
      @available_attributes = Array.new
      @objectclasses        = Array.new
      @errors               = ActiveAccount::Errors.new(self)
      @changed              = Hash.new
      @config               = LdapServers.send(directory_name)
      @human_attributes_map = Hash.new
      @temp                 = HashWithIndifferentAccess.new
      define_user(user)
    end

    def define_user(user)
      if new_account?(user)
        if user.nil?
          @user = HashWithIndifferentAccess.new
        else
          # The blank string is a special case because Array("") => [] whereas what we want is [""]
          @user = user.inject(HashWithIndifferentAccess.new) { |n,(key,value)| n[key] = (value == "" ? [""] : Array(value));n }
        end
      else
        @user = user
        load_available_attributes
        define_user_methods
      end
      if @userid.nil? && user && user[@config[:userid_attribute]]
        @userid = user[@config[:userid_attribute]]
      end
    end

    # FIXME We make this distinction between new and existing
    # accounts though we shouldn't be doing it like we do.
    def new_account?(user = nil)
      not (user ? user : @user).is_a? Net::LDAP::Entry
    end

    def attributes
      @user.instance_variable_get("@myhash")
    end  

    # Implemented in subclasses
    def authenticate(password)
      raise SecurityError.new(:undefined)
    end
    
    ####################
    # Class methods
 
    class << self

      # Find operates with three different retrieval approaches:
      #
      # * Find by userid - This is the login id
      # * Find all - This will return all the entries matched by the conditions used
      # * Find group - This will return all the groups matched by the conditions used
      # * Find filter - This will return all the entries matched by the filter given
      #
      # ==== Parameters
      #
      # * The second parameter is ignored for userid searches.
      # * For all searches, it is a required Hash of attributes and values.
      #   * There is an optional :not hash as well.
      #   * There is an optional :attributes hash as well.
      # * For filter searches, it is a required String that should be a valid LDAP filter
      #
      # ==== Examples
      #
      #   # find by userid
      #   Directory.find('flast')
      #
      #   # find all
      #   Directory.find(:all, :sn => 'Last', :homedirectory => "*file_server_3*", :not => {:title => 'Director'})
      #
      #   # find groups
      #   Directory.find(:group, :cn => 'TestGroup')
      #
      #   # find computers
      #   Directory.find(:computer, :cn => 'My-Computer-01')
      def construct_cn( params )
        return "#{params[:sn]}, #{params[:givenname]} #{params[:initials]}" unless params[:initials].is_empty?
    		return "#{params[:sn]}, #{params[:givenname]}"
      end
      
      def find( *args )
        with_benchmark do
          case args.first
            when :all       then find_every(args.last)
            when :filter    then find_from_filter(args.last)
            when :group     then find_from_group(args.last)
            when :computer  then find_from_computer(args.last)
            else                 find_from_userid(args.first)
          end
        end
      end

      def find_by_list(list, attrib=:samaccountname)
        with_benchmark do
          filter_str = list.inject("") { |join, element| join + "(#{attrib.to_s}=#{element.to_s})" }
          filter_str = "(|#{filter_str})" unless list.size <= 1
          find_from_filter(filter_str)
        end
      end

      private
        # Dynamic attribute finders
        # For example, find_by_uid('lastf99')
        def method_missing(method, *args, &block)
          if method.to_s =~ /^find_by/
            key = method.to_s.scan(/^find_by_(.*)/)[0]
            find(:all, key.first.to_sym => args[0])
          else
            super
          end
        end

        def find_every(conditions)
          entry = self.new
          filter = construct_filter(conditions)
          entry.connect_as_admin
          entry.search_for_collection(filter, {:attributes => conditions[:attributes]})
        end

        def find_from_filter(filter)
          entry = self.new
          entry.connect_as_admin
          entry.search_for_collection(Net::LDAP::Filter.construct(filter))
        end

        def find_from_group(conditions)
          entry = self.new
          filter = construct_filter(conditions)
          entry.connect_as_admin
          entry.search_for_collection(filter, {:conditions => conditions[:attributes], :with_filter => entry.group_filter})
        end

        def find_from_computer(conditions)
          entry = self.new
          filter = construct_filter(conditions)
          entry.connect_as_admin
          entry.search_for_collection(filter, {:conditions => conditions[:attributes], :with_filter => entry.computer_filter})
        end

        def find_from_userid(userid)
          entry = self.new(userid)
          entry.connect_as_admin
          if entry.user_exists?
            entry
          else
            raise EntryNotFound, "Couldn't find an entry with a userid of #{userid}"
          end
        end
          
        def construct_filter(conditions)
          filters = Array.new
          conditions.each do |key,value|
            next if key == :attributes
            if key == :not
              value.each { |k,v| filters << Net::LDAP::Filter.construct("(!(#{k.to_s}=#{v.gsub(/\ /, "*" )}))") }
            else
              filters << Net::LDAP::Filter.eq(key, value)
            end
          end
          filters.inject { |join, filter| join & filter }
        end
      end

    public

    ####################
    # Entry modifying

    def delete_attribute(attribute)
      @user = @user.to_hash
      deleted = @user.delete(attribute.to_s) if @user.respond_to? :delete
      @user = HashWithIndifferentAccess.new(@user)
      return deleted
    end
 
    def []=(attribute, value)
      if attribute =~ /^(dn|distinguishedname)$/i
        raise RuntimeError.new(:unupdatable_attribute)
      end
      value.strip! if value.is_a? String and attribute !~ /unicodepwd/i
      if @user[attribute.to_sym].nil?
        if not (value.nil? or value.empty?)
          @changed[attribute.to_sym] = {:old => @user[attribute.to_sym], :new => value}
          @user[attribute.to_sym] = [value].flatten
        end
      elsif @user[attribute.to_sym].length > 1 || @user[attribute.to_sym].first != value
        @changed[attribute.to_sym] = {:old => @user[attribute.to_sym].first, :new => value}
        @user[attribute.to_sym] = [value].flatten
      end
    end

    def save_without_callbacks(reload = true)
      save(reload, false)
    end

    def save(reload = true, callbacks = true)
      if callbacks
        return false if not valid?
        results = create_or_update
      else
        results = create_or_update_without_callbacks
      end
      if results.is_a? Array
        results.select { |r| r.last.code != 0 }.each do |r|
          errors.add(r.first, r.last.message)
        end
      else
        errors.add(results.message, '') if results.code != 0
      end
      return false if errors && errors.any?
      user_exists? if reload
      @changed.clear
      results
    end

    def add_member(dn)
      connect_as_admin
      add_attribute(self.distinguishedname.first, :member, dn)
    end

    def remove_member(dn)
      Rails.logger.info "Removing #{dn} to group #{self.distinguishedname.first}"
      connect_as_admin
      modify(:dn => self.distinguishedname.first, :operations => [[:delete, :member, dn]])
    end

    def destroy
      connect_as_admin
      delete(:dn => dn)
    end

    def update_attributes(new_attributes, without_saving=false)
      new_attributes.each do |k,v|
        Rails.logger.info "update_attribute: send( #{k.to_s} + '=', #{v} )"
        send(k.to_s + "=", v)
      end
      save unless without_saving
    end

    # Overwrite in a subclass
    def human_attributes_map
      Hash.new
    end

    def human_attribute_name(attribute)
      if human_attributes_map.has_key? attribute.to_sym
        return human_attributes_map[attribute.to_sym]
      end
      attribute
    end

    def system_attributes
      @config[:system_attributes]
    end
 
    private

    def create_or_update
      connect_as_admin
      new_account? ? create : update
    end
  
    def create
      @user = @user.delete_if { |k,v| ( v.first == false ) or v.first.nil? or v.first.empty? }
      attributes = HashWithIndifferentAccess.new
      @user.merge(system_attributes).each { |k,v| attributes[k] = v.flatten }
      distinguishedname = dn
      
      return nil if !distinguishedname
      add(:dn => distinguishedname, :attributes => attributes)
    end

    def update
      results = Array.new
      @changed.each do |attribute,value|
        if((value[:old] != value[:new]) and (not(value[:old].nil? and value[:new].empty?)))
          results << [attribute, replace_attribute(self.distinguishedname.first, attribute, value[:new])]
        end
      end
      results
    end


    ####################
    # Ldap searching
 
    public

    def userid_filter
      if @userid.blank?
        Net::LDAP::Filter.eq(@config[:userid_attribute], self.send(@config[:userid_attribute]).first) 
      else
        Net::LDAP::Filter.eq(@config[:userid_attribute], @userid)
      end
    end

    def user_filter
      Net::LDAP::Filter.construct(@config[:user_filter])
    end

    def group_filter
      Net::LDAP::Filter.construct(@config[:group_filter])
    end

    def computer_filter
      Net::LDAP::Filter.construct(@config[:computer_filter])
    end

    def user_exists?
      search(userid_filter)
    end

    def search_for_collection(filter, options=nil)
      begin
        collection = Array.new
        if options and options.has_key?(:attributes) and not options[:attributes].nil?
          attributes = (Array(options[:attributes]) + [@config[:userid_attribute], 'objectclass']).uniq
        else
          attributes = nil
        end
        puts options.inspect
        puts attributes.inspect
        if options and options.has_key? :with_filter
          with_filter = options[:with_filter]
        else
          with_filter = self.user_filter
        end
        Rails.logger.info "Filter: #{filter & with_filter}"
        Rails.logger.info "Attributes: #{attributes.inspect}"
        @current_connection.search(:filter => (filter & with_filter), :attributes => attributes) do |e|
          userid = e.instance_variable_get("@myhash")[@config[:userid_attribute].to_sym].first
          collection << Kernel.const_get(self.class.to_s.to_sym).send(:new, userid, e) unless userid.nil?
        end
        return collection if not collection.empty?
      rescue => e
        raise RuntimeError.new(:connection_error), e
      end
      nil
    end

    def search(filter, options = nil)
      begin
        if options and options.has_key? :with_filter
          with_filter = options[:with_filter]
        else
          with_filter = self.user_filter
        end
        Rails.logger.info "Filter: #{filter & with_filter}"
        @current_connection.search(:filter => (filter & with_filter)) do |e|
          @user = e
          define_user(@user)
          return true
        end
      rescue Net::LDAP::LdapError
        raise RuntimeError.new(:connection_error)
      end
      nil
    end


    ####################
    # Meta
  
    def method_missing(method, *args, &block)
      # Send ldap mofications to ldap_execute
      if method.to_s =~ /^((modify|(replace|add|delete)_attribute)|add|delete|rename)$/
        ldap_execute(method, *args, &block)

      # Return instance variables
      elsif variable = instance_variables.find { |v| v.sub(/^@/, '').to_sym == method }
        instance_variable_get(variable.to_sym)
  
      # Return attributes
      else
        if new_account?
          if method.to_s =~ /=$/
            @user[method.to_s.sub(/=$/,'').to_sym] = [args.first].flatten
          else
            @user[method]
          end

        elsif self.attributes.has_key? method or methods.include?(method.to_s.downcase)
          if self.attributes.has_key? method
            @user.send(method, *args, &block)
          else
            ''
          end
        else
          ''
        end
      end
    end

    # Grabs the msnyuhealth out of MsnyuhealthAccount
    def directory_name
      self.class.to_s.sub(/Account$/, '').downcase
    end

    # Add self.attribute= methods
    # TODO Should we reload the account after each modification?
    def define_user_methods
      (@available_attributes + self.attributes.keys + %w(:employeenumber homemta homemdb msexchhomeservername)).uniq.each do |attribute|
        self.class.send(:define_method, "#{attribute.to_s}=".to_sym) do |param|
          self[attribute] = param
        end
      end
    end

    def inspect
      output = "#<#{self.class.to_s}:#{sprintf("0x%04x", self.object_id)} @userid=#{@userid}"
      if attributes
        output << " @attributes=#{self.attributes.delete_if { |k,v| k == :password }.inspect}>"
      else
        output << " @user=#{@user.inspect}>"
      end
    end
  end
end
