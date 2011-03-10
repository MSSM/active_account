require 'timeout'
module ActiveAccount
  module Benchmarking
    def self.included(base)
      base.extend(ActiveAccount::Benchmarking::ClassMethods)
    end
    module ClassMethods
      def with_benchmark
        result = nil
        ms = [Benchmark.ms { result = yield }, 0.01].max
        log_message = 'Ldap completed in %.0fms' % ms
        log_message << " (#{self})"
        Rails.logger.info log_message
        result
      end
    end
  end
end
