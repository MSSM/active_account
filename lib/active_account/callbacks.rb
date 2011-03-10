module ActiveAccount
  module Callbacks
    CALLBACKS = %w(
      before_save after_save before_create after_create before_update after_update before_destroy after_destroy before_validation after_validation
    )

    def self.included(base)
      # Define callbacks
      CALLBACKS.each do |callback|
        base.send(:define_method, callback.to_sym) { true }
      end

      # Create callback methods
      [:create_or_update, :valid?, :create, :update, :update_attributes, :destroy].each do |method|
        base.send :alias_method_chain, method, :callbacks
      end
    end

    private

    def create_or_update_with_callbacks
      before_save
      if results = create_or_update_without_callbacks
        puts results.inspect
        after_save
      end
      Array(results)
    end

    def create_with_callbacks
      before_create
      if results = create_without_callbacks
        puts results.inspect
        after_create
      end
      Array(results)
    end

    def update_with_callbacks
      before_update
      if results = update_without_callbacks
        after_update
      end
      Array(results)
    end

    def update_attributes_with_callbacks(*params)
      before_update
      if results = update_attributes_without_callbacks( *params )
        after_update
      end
      results
    end

    def valid_with_callbacks?
      before_validation
      if results = valid_without_callbacks?
        after_validation
      end
      results
    end

    def destroy_with_callbacks
      before_destroy
      if results = destroy_without_callbacks
        after_destroy
      end
      Array(results)
    end
  end
end
