module ActiveAccount

  class Errors < Hash
    def initialize(base, *args)
      @base = base
      super *args
    end

    def add(attribute, message=nil)
      return true if attribute.to_s.empty?
      message ||= "is invalid"
      (self[attribute.to_s] ||= [])<< message
    end

    def add_on_blank( attributes, custom_messaage = nil )
      attributes.each do |attribute|
        value = @base.send(attribute)
        add(attribute, "can't be blank.") if value.nil? or value.first.blank?
      end
    end

    def full_messages(options = Hash.new)
      full_messages = Array.new
  
      each_key do |attribute|
        self[attribute].uniq.each do |message|
          next unless message
          full_messages << @base.human_attribute_name(attribute) + ' ' + message.to_s
        end
      end
      full_messages
    end
  end
end


module ActiveAccount
  module Validations
    def self.included(base)
      base.extend(ActiveAccount::Validations::ClassMethods)
    end

    def valid?
      errors.clear
      validate
      errors.empty?
    end

    # The ClassMethods will overwrite this method
    def validate
    end

    module ClassMethods
      def validates_each(*attributes)
        v = self.instance_method(:validate)
        send(:define_method, :validate) do
          v.bind(self).call
          attributes.each do |attribute|
            yield self, attribute, send(attribute)
          end
        end
      end

      def validates_length_of(*attributes)
        v = self.instance_method(:validate)
        send(:define_method, :validate) do
          v.bind(self).call
          value = send(attributes.first)
          value = (value && (value.is_a? Array) ? value.first : value)
          if value.length != attributes.last[:is]
            errors.add(attributes.first, "must be #{attributes.last[:is]} characters.")
          end
        end
      end

      def validates_presence_of(*attributes)
        v = self.instance_method(:validate)
        send(:define_method, :validate) do
          v.bind(self).call
          errors.add_on_blank(attributes)
        end
      end

      def validates_format_of(*attributes)
        v = self.instance_method(:validate)
        send(:define_method, :validate) do
          v.bind(self).call
          value = send(attributes.first)
          value = (value && (value.is_a? Array) ? value.first : value)
          unless value =~ attributes.last[:with]
            errors.add(attributes.first, "is not in the correct format.")
          end
        end
      end

      def validates_uniqueness_of(*attributes)
        v = self.instance_method(:validate)
        send(:define_method, :validate) do
          v.bind(self).call
          attributes.each do |attribute|
            next if not self.changed.has_key? attribute
            value = send(attribute).first
            if self.class.find(:all, attribute => value, :not => {@config[:userid_attribute] => self.send(@config[:userid_attribute]).first})
              errors.add(attribute, "is not unique across the domain.")
            end
          end
        end
      end
      
      def validates_date_is_current(*attributes)
        v = self.instance_method(:validate)
      
        send(:define_method, :validate) do
          v.bind(self).call                         
          begin
            value = Date.parse_date(send(attributes.first).first)
          rescue
            value = nil
          end
          errors.add(attributes.first, "must be a present or future date.") if value != "0" && !value.blank? && value.beginning_of_day < Time.now.beginning_of_day
        end
      end
    end
  end
end

