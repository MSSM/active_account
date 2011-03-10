module ActiveAccount
  module Mail

    # TODO Just because I like emails formatted like this doesn't mean I need to hardcode it
    def construct_local_mail_part
      begin
        if self.initials.blank? or self.initials.first.empty?
          "#{self.givenname.first.downcase}.#{self.sn.first.downcase}"
        else
          "#{self.givenname.first.downcase}.#{self.initials.first.downcase}.#{self.sn.first.downcase}"
        end
      rescue
        ""
      end.gsub(/\s+/, "").squeeze(".")
    end

    # TODO: This should be grabbed from config
    def global_mail_domains
      %(example.com)
    end

  end
end
