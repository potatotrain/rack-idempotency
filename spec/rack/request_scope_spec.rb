require "spec_helper"
require "rack/lint"

RSpec.describe Rack::Idempotency do
  let(:store) { Rack::Idempotency::MemoryStore.new }
  let(:received_inputs) { [] }
  let(:app) do
    lambda do |env|
      received_inputs << env["rack.input"]
      [status, { "content-type" => "text/plain", "set-cookie" => "session=response-cookie" }, [SecureRandom.uuid]]
    end
  end
  let(:status) { 200 }
  let(:middleware) { described_class.new(app, store: store) }
  let(:request) { Rack::MockRequest.new(middleware) }
  let(:key) { SecureRandom.uuid }
  let(:headers) do
    {
      "HTTP_IDEMPOTENCY_KEY" => key,
      "HTTP_AUTHORIZATION" => "Bearer first-token",
      "HTTP_COOKIE" => "session=first-session; auth=first-auth"
    }
  end

  def send_request(method: "POST", path: "/api/v1/chat_messages?source=mobile", input: "message=hello", **overrides)
    request.request(method, path, headers.merge(overrides).merge(input: input))
  end

  {
    "another token" => { "HTTP_AUTHORIZATION" => "Bearer second-token" },
    "another dashed Authorization alias" => { "X-HTTP_AUTHORIZATION" => "Bearer second-token" },
    "another underscored Authorization alias" => { "X_HTTP_AUTHORIZATION" => "Bearer second-token" },
    "another redirected Authorization alias" => { "REDIRECT_X_HTTP_AUTHORIZATION" => "Bearer second-token" },
    "no authorization header" => { "HTTP_AUTHORIZATION" => nil },
    "another auth cookie" => { "HTTP_COOKIE" => "session=first-session; auth=second-auth" },
    "another session cookie" => { "HTTP_COOKIE" => "session=second-session; auth=first-auth" },
    "no cookies" => { "HTTP_COOKIE" => nil },
    "another method" => { method: "PUT" },
    "another path" => { path: "/api/v1/users?source=mobile" },
    "another query string" => { path: "/api/v1/chat_messages?source=web" },
    "another mount path" => { "SCRIPT_NAME" => "/mounted" }
  }.each do |description, changes|
    it "does not replay the same key for #{description}" do
      original = send_request
      different = send_request(**changes)

      expect(different.body).not_to eq(original.body)
      expect(received_inputs.size).to eq(2)
    end
  end

  [200, 302].each do |response_status|
    context "with a #{response_status} response" do
      let(:status) { response_status }

      it "replays the identical request including its status, headers and body" do
        original = send_request
        replay = send_request

        expect(replay.status).to eq(original.status)
        expect(replay.headers).to eq(original.headers)
        expect(replay.body).to eq(original.body)
        expect(received_inputs.size).to eq(1)
      end
    end
  end

  %w[HTTP_AUTHORIZATION X-HTTP_AUTHORIZATION X_HTTP_AUTHORIZATION REDIRECT_X_HTTP_AUTHORIZATION HTTP_COOKIE].each do |header|
    it "replays when #{header} is the only credential header" do
      headers.clear
      headers.merge!("HTTP_IDEMPOTENCY_KEY" => key, header => "first-credential")
      original = send_request

      expect(send_request.body).to eq(original.body)
      expect(send_request(header => "second-credential").body).not_to eq(original.body)
      expect(received_inputs.size).to eq(2)
    end
  end

  [nil, ""].each do |credential|
    it "does not cache requests with #{credential.nil? ? 'missing' : 'empty'} credentials" do
      headers.merge!("HTTP_AUTHORIZATION" => credential, "HTTP_COOKIE" => credential)
      expect(store).not_to receive(:read)
      expect(store).not_to receive(:write)

      original = send_request
      expect(send_request.body).not_to eq(original.body)
      expect(received_inputs.size).to eq(2)
    end
  end

  ["/oauth/token", "/oauth/token.json", "/oauth/authorize?source=mobile", "/oauth/revoke", "//oauth/token", "///oauth/token"].each do |path|
    it "never caches #{path}, including when the app is mounted" do
      expect(store).not_to receive(:read)
      expect(store).not_to receive(:write)

      ["", "/mounted"].each do |mount|
        overrides = { "SCRIPT_NAME" => mount, "PATH_INFO" => path.split("?").first }
        original = send_request(path: path, **overrides)
        expect(send_request(path: path, **overrides).body).not_to eq(original.body)
      end
      expect(received_inputs.size).to eq(4)
    end
  end

  it "replays a multipart retry whose boundary changed" do
    responses = %w[first-boundary second-boundary].map do |boundary|
      body = "--#{boundary}\r\nContent-Disposition: form-data; name=\"message\"\r\n\r\nhello\r\n--#{boundary}--\r\n"
      send_request(input: body, "CONTENT_TYPE" => "multipart/form-data; boundary=#{boundary}")
    end

    expect(responses.last.body).to eq(responses.first.body)
    expect(received_inputs.size).to eq(1)
    expect(received_inputs.first.read).to include("hello")
  end

  it "does not cache an app mounted at /oauth" do
    expect(store).not_to receive(:read)
    expect(store).not_to receive(:write)

    original = send_request(path: "/token", "SCRIPT_NAME" => "/oauth")
    expect(send_request(path: "/token", "SCRIPT_NAME" => "/oauth").body).not_to eq(original.body)
  end

  [true, false].each do |rewindable|
    it "never reads or rewinds a large #{rewindable ? 'rewindable' : 'non-rewindable'} input" do
      input = double("large input")
      allow(input).to receive(:rewind) if rewindable
      expect(input).not_to receive(:read)
      expect(input).not_to receive(:rewind)
      allow(input).to receive(:respond_to?).with(:rewind).and_return(rewindable)
      env = Rack::MockRequest.env_for("/api/v1/chat_messages", method: "POST").merge(headers)
      env.merge!("rack.input" => input, "CONTENT_LENGTH" => "314572800", "CONTENT_TYPE" => "application/octet-stream")

      original = middleware.call(env)
      expect(middleware.call(env.dup)).to eq(original)
      expect(received_inputs).to eq([input])
    end
  end

  it "does not conflate header boundaries" do
    original = send_request("HTTP_AUTHORIZATION" => "a", "HTTP_COOKIE" => "bc")
    different = send_request("HTTP_AUTHORIZATION" => "ab", "HTTP_COOKIE" => "c")

    expect(different.body).not_to eq(original.body)
  end

  %w[HTTP_AUTHORIZATION HTTP_COOKIE].each do |header|
    it "scopes #{header} by its bytes without requiring UTF-8" do
      original = send_request(header => "first-\xFF".b)

      expect(send_request(header => "first-\xFF".b).body).to eq(original.body)
      expect(send_request(header => "second-\xFE".b).body).not_to eq(original.body)
      expect(received_inputs.size).to eq(2)
    end
  end

  context "after upstream checked a JSON request for form parameters" do
    let(:middleware) do
      idempotency = super()
      Rack::Lint.new(lambda do |env|
        Rack::Request.new(env).POST
        idempotency.call(env)
      end)
    end

    it "preserves replay through Rack::Lint without changing the downstream body" do
      original = send_request(input: '{"message":"hello"}', "CONTENT_TYPE" => "application/json")
      replay = send_request(input: '{"message":"hello"}', "CONTENT_TYPE" => "application/json")

      expect(replay.body).to eq(original.body)
      expect(received_inputs.size).to eq(1)
      expect(received_inputs.first.read).to eq('{"message":"hello"}')
    end
  end

  it "uses a new opaque namespace instead of previous unsafe cache entries" do
    old_response = [200, {}, ["other-caller"]].to_json
    allow(store).to receive(:read).and_return(old_response)
    expect(store).to receive(:read).with(match(/\Arack:idempotency:v3:[0-9a-f]{64}\z/)).and_return(nil)
    expect(store).to receive(:write).with(match(/\Arack:idempotency:v3:[0-9a-f]{64}\z/), anything).and_call_original

    expect(send_request.body).not_to eq("other-caller")
    expect(received_inputs.size).to eq(1)
  end
end
