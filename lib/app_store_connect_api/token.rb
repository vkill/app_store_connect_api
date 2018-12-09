require "jwt"

module AppStoreConnectApi
  class Token

    attr_reader :key_id, :issuer_id, :auth_key_p8_content

    def initialize(key_id, issuer_id, auth_key_p8)
      @key_id = key_id
      @issuer_id = issuer_id
      @auth_key_p8_content = File.exists?(auth_key_p8) ? open(auth_key_p8).read : auth_key_p8
    end

    def generate
      if @token and @exp and @exp > Time.now.to_i
        @token
      else
        @token = force_generate { |exp| @exp = exp }
      end
    end

    private

    def force_generate
      header = {
        alg: "ES256",
        kid: key_id,
        typ: "JWT"
      }

      exp = Time.now.to_i + 60 * 20

      payload = {
        iss: issuer_id,
        exp: exp,
        aud: "appstoreconnect-v1"
      }

      private_key = OpenSSL::PKey::EC.new auth_key_p8_content

      yield exp if block_given?

      JWT.encode payload, private_key, 'ES256', header
    end

  end
end
