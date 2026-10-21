require "rack/request"
require "digest/sha2"
require "stringio"

module Rack
  class Idempotency    
    class Request < Rack::Request
      SCOPE_HEADERS = %w[HTTP_AUTHORIZATION X-HTTP_AUTHORIZATION X_HTTP_AUTHORIZATION REDIRECT_X_HTTP_AUTHORIZATION HTTP_COOKIE].freeze

      def idempotency_key
        get_header("HTTP_IDEMPOTENCY_KEY").tap do |key|
          unless key.nil? || key.match?(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
            raise InsecureKeyError.new(env), 'Idempotency-Key must be a valid UUID'
          end
        end
      end

      def fingerprint
        raw_body = request_body
        return unless raw_body

        fields = [idempotency_key, request_method, fullpath, *SCOPE_HEADERS.map { |header| get_header(header) }, raw_body]
        Digest::SHA256.hexdigest(fields.map { |field| Digest::SHA256.hexdigest(field.to_s) }.join)
      end

      private

      def request_body
        return get_header("RAW_POST_DATA") if get_header("RAW_POST_DATA")
        return "" unless body
        return read_rewindable_body if body.respond_to?(:rewind)

        form = get_header("rack.request.form_vars")
        return form if form && content_length && content_length.to_i == form.bytesize

        raw_body = body.read
        set_header("rack.input", StringIO.new(raw_body))
        raw_body if content_length && content_length.to_i == raw_body.bytesize
      end

      def read_rewindable_body
        body.rewind
        body.read
      ensure
        body.rewind
      end
    end
  end
end
