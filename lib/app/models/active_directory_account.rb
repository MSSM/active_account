module ActiveAccount::GroupTypes
  GROUP_TYPES = {
    -2147483646 => "Global Security Group",
    -2147483644 => "Local Security Group",
    -2147483643 => "BuiltIn Group",
    -2147483640 => "Universal Security Group",
              2 => "Global Distribution Group",
              4 => "Local Distribution Group",
              8 => "Universal Distribution Group"
  }
  def interpret_group_type
    GROUP_TYPES[self.grouptype.first.to_i]
  end
  def distribution_list?
    self.grouptype.first.to_i > 0
  end
  def security_group?
    not distribution_list?
  end
end

module ActiveAccount::UACFlags
  UAC_FLAGS = {
    0x00000001	=> {:flag => "ADS_UF_SCRIPT",                                 :message => "Login script"},
    0x00000002	=> {:flag => "ADS_UF_ACCOUNTDISABLE",                         :message => "Account disabled"},
    0x00000008	=> {:flag => "ADS_UF_HOMEDIR_REQUIRED",                       :message => "Home directory"},
    0x00000010	=> {:flag => "ADS_UF_LOCKOUT",                                :message => "Account locked"},
    0x00000020	=> {:flag => "ADS_UF_PASSWD_NOTREQD",                         :message => "Password not required"},
    0x00000040	=> {:flag => "ADS_UF_PASSWD_CANT_CHANGE",                     :message => "Password cannot change"},
    0x00000080	=> {:flag => "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED",        :message => "Encrypted password"},
    0x00000100	=> {:flag => "ADS_UF_TEMP_DUPLICATE_ACCOUNT",                 :message => "Local user account"},
    0x00000200	=> {:flag => "ADS_UF_NORMAL_ACCOUNT",                         :message => "Normal account"},
    0x00000800	=> {:flag => "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT",              :message => "Interdomain trusted account"},
    0x00001000	=> {:flag => "ADS_UF_WORKSTATION_TRUST_ACCOUNT",              :message => "Interdomain trusted computer"},
    0x00002000	=> {:flag => "ADS_UF_SERVER_TRUST_ACCOUNT",                   :message => "Domain controller"},
    0x00010000	=> {:flag => "ADS_UF_DONT_EXPIRE_PASSWD",                     :message => "Password does not expire"},
    0x00020000	=> {:flag => "ADS_UF_MNS_LOGON_ACCOUNT",                      :message => "MNS account"},
    0x00040000	=> {:flag => "ADS_UF_SMARTCARD_REQUIRED",                     :message => "Smartcard required"},
    0x00080000	=> {:flag => "ADS_UF_TRUSTED_FOR_DELEGATION",                 :message => "Service delegation"},
    0x00100000	=> {:flag => "ADS_UF_NOT_DELEGATED",                          :message => "No service delegation"},
    0x00200000	=> {:flag => "ADS_UF_USE_DES_KEY_ONLY",                       :message => "DES required"},
    0x00400000	=> {:flag => "ADS_UF_DONT_REQUIRE_PREAUTH",                   :message => "No kerberos"},
    0x00800000	=> {:flag => "ADS_UF_PASSWORD_EXPIRED",                       :message => "Password expired"},
    0x01000000	=> {:flag => "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", :message => "Service authentication delegation"}
  }

  SYMBOL_TO_UAC_FLAGS = UAC_FLAGS.inject({}) do |hash,(code,attribute)|
    hash[attribute[:message].downcase.gsub(/ /,'_').to_sym] = code
    hash
  end

  def interpret_flag(flag)
    case flag
      when Fixnum then
        UAC_FLAGS[flag]
      when Symbol then
        SYMBOL_TO_UAC_FLAGS[flag]
    end
  end

  def status
    uac_has_flag?(:account_disabled) ? "disabled" : "active"
  end
end

module ActiveAccount::ADTimestamps
  EPOCH = 116_444_736_000_000_000
  MULTIPLIER = 10_000_000

  def self.included(base)
    base.extend(ActiveAccount::ADTimestamps::ClassMethods)
  end

  def ad_to_time(time)
    time = time.first if time.class == Array
    return '' if time.to_i == 0
    begin
      Time.at((time.to_i - EPOCH) / MULTIPLIER)
    rescue RangeError
      begin 
        Time.parse time
      rescue
        ''
      end
    end
  end

  def time_to_ad(time)
    time = time.first if time.respond_to? :first
    (time.to_i * MULTIPLIER) + EPOCH
  end
  
  module ClassMethods
    def time_to_ad(time)
      self.new.time_to_ad(time)
    end
    def ad_to_time(time)
      self.new.ad_to_time(time)
    end
  end
end

class ActiveDirectoryAccount < ActiveAccount::Base
  include ActiveAccount::ADTimestamps
  include ActiveAccount::GroupTypes
  include ActiveAccount::UACFlags

  def before_save
    handle_account_expiration
  end

  def before_create
    self.unicodepwd = encode_password(generate_password)
    self.pwdlastset = '0'
    self.displayname = self.cn.first
    self.userprincipalname = self.samaccountname.first + "@" + @config[:domain]
  end

  def set_mail_attributes
    return nil if self.samaccountname.empty? or self.samaccountname.first.empty?
    self.mailnickname = self.construct_local_mail_part
  end

  def handle_account_expiration
    return nil if self.accountexpires.nil?
    if self.accountexpires.empty? or self.accountexpires.first.empty?
      self.accountexpires = '0'
    elsif self.accountexpires.first !~ /^[0-9]+$/
      begin
        self.accountexpires = time_to_ad(Time.parse(self.accountexpires.first)).to_s
      rescue
        nil
      end
    end    
  end

  def construct_common_name
    begin
    if self.initials.nil? or self.initials.empty? or self.initials.first.empty?
      "#{self.sn.first}, #{self.givenname.first}"
    else
      "#{self.sn.first}, #{self.givenname.first} #{self.initials.first}"
    end
    rescue
      "#{self.sn.first}, #{self.givenname.first}"
    end
  end

  def update_common_name
    old_cn = self.cn
    new_cn = construct_common_name
    if new_account?
      self.cn = new_cn
    elsif old_cn.map { |e| e.downcase } != new_cn.map { |e| e.downcase }
      self.cn = new_cn
      rename(:olddn             => self.distinguishedname.first,
             :newrdn            => "cn=#{self.cn.first.gsub(/,/, '\,')}",
             :delete_attributes => true)
      self.distinguishedname = self.distinguishedname.first.gsub(/cn=#{old_cn}/i, "cn=#{self.cn.first.gsub( /,/, '\,' )}")
    end
  end


  ####################
  # Mail

  def mail_enabled?
    begin
      unless self.mail_user.blank?
        if self.mail_user.first == '1'
          return true
        elsif self.mail_user.first == '0'
          return false
        else
          return self.mail_user
        end
      end
    rescue
    end
    return (not self.mail.nil? and not self.mail.first.empty?)
  end

  def update_proxy_addresses( proxy_addresses )
    return true if proxy_addresses.nil?
    self.proxyaddresses = proxy_addresses.values.map { |p| p.values }.flatten.delete_if { |v| v.empty? }.uniq.map { |p| 'smtp:' + p }
    proxy_addresses.values.map { |p| p.values }.flatten.delete_if { |v| v.empty? }.uniq.map { |p| 'smtp:' + p }.each do |p|
      if not self.proxyaddresses.include? p
        self.proxyaddresses << p
      end
    end
  end

  def construct_proxy_addresses!
    return false if self.samaccountname.first.nil?
    local_part = construct_local_mail_part
    self.mail = local_part + '@' + @config[:mail_domain]
    proxy_addresses = [
      'SMTP:' + self.mail.first,
      'smtp:' + local_part + '@' + @config[:domain],
      'smtp:' + self.samaccountname.first + '@' + @config[:domain],
      'smtp:' + self.samaccountname.first + '@' + @config[:mail_domain]
    ]
    global_mail_domains.each do |domain|
      proxy_addresses << 'smtp:' + local_part + '@' + domain
    end
    if self.proxyaddresses.nil?
      self.proxyaddresses = proxy_addresses
    else
      proxy_addresses.each do |pa|
        unless self.proxyaddresses.include? pa
          self.proxyaddresses << pa
        end
      end
    end
  end

  def last_logon
    last_logon_time = self.ad_to_time(self.lastlogon)
    if last_logon_time.is_a? Time
      last_logon_time.strftime("%B %d, %Y at %l:%M %p")
    else
      "Never"
    end
  end

  ####################
  # Password

  def uac_has_flag?(flag)
    self.useraccountcontrol.first.to_i & self.interpret_flag(flag) > 0
  end

  def password_expires_on
    password_last_set = self.pwdlastset.first.to_i
    expires = String.new
    if uac_has_flag?(:password_does_not_expire)
      expires = "Password does not expire"
    elsif password_last_set == 0
      expires = "Password must be changed at next login"
    elsif password_last_set == -1
      expires = "Account does not have a password"
    else
      expires = ad_to_time(self.class.maximum_password_age.to_i + password_last_set)
      expires = String.new if expires < Time.now
    end
    return expires
  end

  class << self
    def maximum_password_age
      begin
        klass = self.new
        klass.connect_as_admin
        result = klass.current_connection.search(:base => klass.config[:base], :scope => Net::LDAP::SearchScope_BaseObject, :attributes => ['maxpwdage'])
        age = (result.first[:maxpwdage].first.to_i * -1)
        age
      rescue
      end
    end
  end
 
  def reset_password(new_password)
    connect_as_admin
    if connected?
      if user_exists?
        unlock_account if account_locked?
        result = replace_attribute(@user.distinguishedname.first, :unicodepwd, encode_password(new_password))
        force_password_reset
        return result
      end
      raise SecurityError.new(:userid)
    end
    raise RuntimeError.new(:connection_error)
  end

  def change_password(old_password, new_password)
    authenticate(old_password)
    unlock_account if account_locked?
    ops = [[:delete, :unicodepwd, encode_password(old_password)],
           [:add,    :unicodepwd, encode_password(new_password)]]
    result = modify(:dn => @user.distinguishedname.first, :operations => ops)
    raise SecurityError.new(:format) if result.code == 19
    return result
  end

  def authenticate(password)
    raise SecurityError.new(:password) if password.blank?
    connect_as_admin
    if connected?
      if user_exists?
        if force_password_change?
          reset_password = true
          unlock_account
        end
        connect("#{@userid}@#{@config[:domain]}", password)
        if connected?
          force_password_reset unless reset_password.nil?
          return true
        end
        force_password_reset unless reset_password.nil?
        raise SecurityError.new(:password)
      end
      raise SecurityError.new(:userid)
    end
    raise RuntimeError.new(:connection_error)
  end

  def force_password_change?
    self.pwdlastset.first == '0'
  end

  def force_password_reset
    connect_as_admin
    begin
      replace_attribute(@user.distinguishedname.first, :pwdlastset, '0')
    rescue
      raise RuntimeError.new(:connection_error)
    end
  end

  def unlock_account
    begin
      if @user.badpwdcount.first != '0'
        replace_attribute(@user.distinguishedname.first, :badpwdcount, '0')
      end
    rescue
      replace_attribute(@user.distinguishedname.first, :badpwdcount, '0')
    end
    ops = Array.new
    ops << [:replace, :lockouttime,        '0'  ]
    ops << [:replace, :pwdlastset,         '-1' ] if @user.pwdlastset.first == '0'
    ops << [:replace, :useraccountcontrol, '512'] if @user.useraccountcontrol.first == '514'
    begin
      modify(:dn => @user.distinguishedname.first, :operations => ops)
    rescue
      raise RuntimeError.new(:connection_error)
    end
  end

  def account_locked?
    self.lockouttime.first != '0' || self.badpwdcount.first != '0' || self.pwdlastset.first == '0' || self.useraccountcontrol.first == '514'
  end


  ####################
  # Groups

  def groups
    groups = Array.new
    self.memberof.each do |group|
      groups << group
      groups << get_parent_groups(group) if group =~ /^CN=Chief/i
    end
    groups.flatten.uniq.map do |group|
      if(m = group.match(/^CN=(\w+)/i))
        m[1]
      end unless group.nil?
    end.delete_if { |g| g.nil? }
  end

  def get_parent_groups(group)
    parent_group = self.class.find(:group, :distinguishedname => group)
    if parent_group and parent_group.first.class == self.class
      return parent_group.first.memberof if parent_group.first.memberof.any? 
    end
  end
  

  ####################
  # Helpers

  def encode_password(userpassword)
    encoded = String.new
    userpassword = "\"#{userpassword}\""
    userpassword.length.times { |i| encoded << "#{userpassword[i..i]}\000" }
    return encoded
  end

  def generate_password
    (0...8).map{65.+(rand(25)).chr}.join
  end

  def human_attributes_map
    {
      :cn                         => 'name',
      :sn                         => 'last name',
      :info                       => 'manager',
      :givenname                  => 'first name',
      :employeeid                 => 'life number',
      :employeenumber             => 'life number',
      :samaccountname             => 'login',
      :accountexpires             => 'account expiration',
      :telephonenumber            => 'telephone number',
      :physicaldeliveryofficename => 'location'
    }
  end

  def load_available_attributes
    super
    temp = @available_attributes.select { |e| e } 
    temp << 'info'
    @available_attributes = temp
  end
end
