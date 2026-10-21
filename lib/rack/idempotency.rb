require "json"

require "rack/idempotency/version"

require "rack/idempotency/errors"
require "rack/idempotency/memory_store"
require "rack/idempotency/null_store"
require "rack/idempotency/request"
require "rack/idempotency/request_storage"
require "rack/idempotency/response"

module Rack
  # Rack middleware for ensuring mutating endpoints are called at most once.
  #
  # Requests with an `Idempotency-Key` and Authorization or Cookie header
  # outside /oauth/ store successful responses in the given cache. Retries
  # with the same key, method, full path and credentials replay that response.
  class Idempotency
    def initialize(app, store: NullStore.new)
      @app     = app
      @store   = store
    end

    def call(env)
      request = Request.new(env.dup.freeze)
      storage = RequestStorage.new(@store, request)

      storage.read || store_response(storage, env)
    end

    private

    def store_response(storage, env)
      response = Response.new(*@app.call(env))

      storage.write(response) if response.success?

      [response.status, response.headers, response.body]
    end
  end
end
