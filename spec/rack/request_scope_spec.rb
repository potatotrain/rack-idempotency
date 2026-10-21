require "spec_helper"
require "rack/lint"
require "rack/method_override"

RSpec.describe Rack::Idempotency do
  let(:store) { Rack::Idempotency::MemoryStore.new }
  let(:received_bodies) { [] }
  let(:app) do
    lambda do |env|
      received_bodies << env["rack.input"]&.read
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
  let(:body) { "grant_type=password&username=first&password=first-password" }

  def send_request(method: "POST", path: "/oauth/token?source=mobile", input: body, **overrides)
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
    "another query string" => { path: "/oauth/token?source=web" },
    "another mount path" => { "SCRIPT_NAME" => "/mounted" },
    "another body" => { input: "grant_type=password&username=second&password=second-password" }
  }.each do |description, changes|
    it "does not replay the same key for #{description}" do
      original = send_request
      different = send_request(**changes)

      expect(different.body).not_to eq(original.body)
      expect(received_bodies.size).to eq(2)
    end
  end

  ["Basic shared-community-credentials", nil].each do |authorization|
    context "with #{authorization ? 'shared Basic credentials' : 'client credentials in the body'}" do
      let(:headers) { super().merge("HTTP_AUTHORIZATION" => authorization, "HTTP_COOKIE" => nil) }
      let(:body) { "client_id=shared&client_secret=shared&grant_type=password&username=first&password=first-password" }

      it "does not replay another user's password grant" do
        original = send_request
        different = send_request(input: body.sub("first-password", "second-password"))

        expect(different.body).not_to eq(original.body)
        expect(received_bodies.size).to eq(2)
      end
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
        expect(received_bodies).to eq([body])
      end
    end
  end

  it "hashes the entire body even when upstream middleware has read it" do
    first_input = StringIO.new(body)
    second_input = StringIO.new(body.sub("first-password", "second-password"))
    first_input.read
    second_input.read

    original = send_request(input: first_input)
    different = send_request(input: second_input)

    expect(different.body).not_to eq(original.body)
    expect(received_bodies).to eq([body, body.sub("first-password", "second-password")])
  end

  it "handles binary request bodies without decoding them" do
    original = send_request(input: "\xFF\x00".b)
    replay = send_request(input: "\xFF\x00".b)
    different = send_request(input: "\xFE\x00".b)

    expect(replay.body).to eq(original.body)
    expect(different.body).not_to eq(original.body)
    expect(received_bodies).to eq(["\xFF\x00".b, "\xFE\x00".b])
  end

  it "does not conflate header boundaries" do
    original = send_request("HTTP_AUTHORIZATION" => "a", "HTTP_COOKIE" => "bc")
    different = send_request("HTTP_AUTHORIZATION" => "ab", "HTTP_COOKIE" => "c")

    expect(different.body).not_to eq(original.body)
  end

  it "preserves non-rewindable request bodies while separating different bodies" do
    first_input = double("non-rewindable input", size: body.bytesize)
    second_input = double("non-rewindable input", size: "another body".bytesize)
    expect(first_input).to receive(:read).once.and_return(body)
    expect(second_input).to receive(:read).once.and_return("another body")

    original = send_request(input: first_input)
    different = send_request(input: second_input)
    replay = send_request

    expect(different.body).not_to eq(original.body)
    expect(replay.body).to eq(original.body)
    expect(received_bodies).to eq([body, "another body"])
  end

  context "after Rack has parsed a non-rewindable form" do
    let(:middleware) { Rack::Lint.new(Rack::MethodOverride.new(super())) }
    let(:headers) { super().merge("CONTENT_TYPE" => "application/x-www-form-urlencoded") }

    it "uses the complete form bytes to separate password grants and preserve retries" do
      original = send_request
      different = send_request(input: body.sub("first-password", "second-password"))
      replay = send_request

      expect(different.body).not_to eq(original.body)
      expect(replay.body).to eq(original.body)
      expect(received_bodies.size).to eq(2)
    end

    it "does not cache when the original body cannot be recovered exactly" do
      input = body + "\0"
      send_request(input: input)
      send_request(input: input)

      expect(received_bodies.size).to eq(2)
    end
  end

  it "handles a request without rack.input" do
    original = send_request(input: nil)
    replay = send_request(input: nil)

    expect(replay.body).to eq(original.body)
    expect(received_bodies).to eq([nil])
  end

  it "leaves bodies untouched when there is no idempotency key" do
    input = double("non-rewindable input")
    expect(input).to receive(:read).once.and_return(body)

    send_request(input: input, "HTTP_IDEMPOTENCY_KEY" => nil)

    expect(received_bodies).to eq([body])
  end

  it "does not put credentials or raw body contents in cache keys" do
    expect(store).to receive(:write).with(satisfy { |cache_key|
      ["first-token", "first-session", "first-auth", "first-password"].none? { |secret| cache_key.include?(secret) }
    }, anything).and_call_original

    send_request
  end

  it "does not read cached responses stored under an unscoped key" do
    store.write("rack:idempotency:#{key}", [200, { "set-cookie" => "session=other-caller" }, ["other-caller"]].to_json)

    expect(send_request.body).not_to eq("other-caller")
    expect(received_bodies).to eq([body])
  end
end
