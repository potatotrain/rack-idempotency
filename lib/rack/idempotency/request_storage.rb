module Rack
  class Idempotency
    class RequestStorage
      def initialize(store, request)
        @store   = store
        fingerprint = request.fingerprint if request.idempotency_key
        @storage_key = "rack:idempotency:v3:#{fingerprint}" if fingerprint
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
    end
  end
end
