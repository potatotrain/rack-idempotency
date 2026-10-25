require "spec_helper"

RSpec.describe Rack::Idempotency do
  let(:store) { Rack::Idempotency::MemoryStore.new }
  let(:calls) { [] }
  let(:app) do
    lambda do |env|
      calls << env
      [200, { "content-type" => "text/plain" }, [SecureRandom.uuid]]
    end
  end
  let(:fingerprint) { ->(request) { request.get_header("HTTP_AUTHORIZATION") } }
  let(:middleware) { described_class.new(app, store: store, fingerprint: fingerprint) }
  let(:request) { Rack::MockRequest.new(middleware) }
  let(:key) { SecureRandom.uuid }

  def send_request(authorization, idempotency_key: key)
    request.post("/", "HTTP_IDEMPOTENCY_KEY" => idempotency_key, "HTTP_AUTHORIZATION" => authorization)
  end

  it "replays a retry with the same fingerprint" do
    original = send_request("Bearer first")

    expect(send_request("Bearer first").body).to eq(original.body)
    expect(calls.size).to eq(1)
  end

  it "does not replay a retry with another fingerprint" do
    original = send_request("Bearer first")

    expect(send_request("Bearer second").body).not_to eq(original.body)
    expect(calls.size).to eq(2)
  end

  it "skips the store when the fingerprint is nil" do
    expect(store).not_to receive(:read)
    expect(store).not_to receive(:write)

    2.times { send_request(nil) }
    expect(calls.size).to eq(2)
  end

  it "stores the response under the key and the digest of the fingerprint" do
    send_request("Bearer first")

    expect(store.read("rack:idempotency:#{key}:#{Digest::SHA256.hexdigest('Bearer first')}")).to be_a(String)
  end

  it "calls the fingerprint once, and only for requests with a key" do
    expect(fingerprint).to receive(:call).once.and_call_original

    send_request("Bearer first")
    send_request("Bearer first", idempotency_key: nil)
  end

  context "without a fingerprint" do
    let(:fingerprint) { nil }

    it "stores the response under the key alone" do
      send_request("Bearer first")

      expect(store.read("rack:idempotency:#{key}")).to be_a(String)
    end

    it "does not cache requests without a key" do
      2.times { send_request("Bearer first", idempotency_key: nil) }

      expect(calls.size).to eq(2)
    end
  end
end
