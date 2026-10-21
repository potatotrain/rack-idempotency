require "rack/request"
require "digest/sha2"

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
        return if [path, path_info].any? { |value| value.squeeze("/").start_with?("/oauth/") }

        credentials = SCOPE_HEADERS.map { |header| get_header(header).to_s }
        return if credentials.all?(&:empty?)

        fields = [idempotency_key, request_method, fullpath, *credentials]
        Digest::SHA256.hexdigest(fields.map { |field| Digest::SHA256.hexdigest(field) }.join)
      end
    end
  end
end
