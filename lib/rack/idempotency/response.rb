module Rack
  class Idempotency
    class Response
      attr_reader :status, :headers, :body

      def initialize(status, headers, body)
        @status  = status.to_i
        @headers = headers
        @body    = body
      end

      def success?
        status.to_i >= 200 && status.to_i < 400
      end

      def to_a
        [status, headers.to_hash, body.each(&:to_s)]
      end

      def to_json
        to_a.to_json
      end
    end
  end
end
