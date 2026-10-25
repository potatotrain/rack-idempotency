require "digest/sha2"

module Rack
  class Idempotency
    class RequestStorage
      def initialize(store, request, fingerprint)
        @store       = store
        @storage_key = storage_key_for(request, fingerprint)
      end

      def read
        return unless storage_key

        stored = store.read(storage_key)
        JSON.parse(stored) if stored
      end

      def write(response)
        return unless storage_key

        store.write(storage_key, response.to_json)
      end

      private

      attr_reader :store
      attr_reader :storage_key

      def storage_key_for(request, fingerprint)
        key = request.idempotency_key
        return unless key
        return "rack:idempotency:#{key}" unless fingerprint

        scope = fingerprint.call(request)
        "rack:idempotency:#{key}:#{Digest::SHA256.hexdigest(scope)}" if scope
      end
    end
  end
end
