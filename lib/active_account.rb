module ActiveAccount
  LDAP_CONFIG_FILE = ::Rails.root.to_s + "/config/ldap.yml"
  LdapServers = OpenStruct.new(HashWithIndifferentAccess.new(YAML.load(ERB.new(File.read(LDAP_CONFIG_FILE)).result)[::Rails.env]))

  Directories = Dir.glob(::Rails.root.to_s + "/app/models/*_account.rb").map do |file|
    file.scan(/\/([a-z]+)_account\.rb$/i)
  end.flatten.map { |e| e.capitalize }
end

ActiveAccount::Base.class_eval do
  include ActiveAccount::Ldap
  include ActiveAccount::Validations
  include ActiveAccount::Callbacks
  include ActiveAccount::Mail
  include ActiveAccount::Benchmarking
end

%w{ models controllers }.each do |dir|
  path = File.join(File.dirname(__FILE__), "app", dir)
  $LOAD_PATH << path
  ActiveSupport::Dependencies.autoload_paths << path
end

