require 'json/jwt'
module Fluent
  # JwtFilter
  # Encrypt/Decript JSON message using JSON Web Token Technology
  # For encryption, JSON Web Key (public) is used
  # For decryption, JSON Web Key (private) is used
  # Currently symmetric key is not supported in JSON Web Key (TODO)
  #
  # Example encrypted JSON message is as follows:
  # {"jwe_encrypted":
  #   {
  #     "protected": "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81In0",
  #     "encrypted_key": "P8dKW8KE5nJm7s9GDENrcSW2iNw0Fo4FqDxRwyr6JSGCPCwjc_agoEq7O8xhWX_WoRZin90ORPP1oO5_kavTIcppnRcmquxm1jhQtKk77-HN9Efo7DQf3yfgdnD7xv-M1I_rCPeHVFm33BNB6TIhCo1fUfhEUM8GjjC8PLFFwOcDUNf1vw1-WjUqMhUf-b45s6CHhYdpDqzs7GYuovDo0LMeFeBSc4Xntw_vWPMeHxsuVyuZpDHUQm-dX5wnmQ4UhZPzEhkkVJw1oz2uTMjcl6mi1bucKGy1zNaGN-JEhg5_2QgijqTxRtJgOBlVtHLJ5HABT4tI6-v06M3dPryz5w",
  #     "iv": "xYk2s_39pHvLBZy3",
  #     "ciphertext": "taCQAMBZtKgQfh5LaWs",
  #     "tag": "nbWyhG82A-eCJMvdhbrSJw"
  #   }
  # }
  #
  # If some attributes added to the contents during the transfer,
  # the decrypted contents are merged into the modified hash.
  class JwtFilter < Filter
    # Register this filter as "jwt"
    Plugin.register_filter("jwt", self)

    config_param :method, :string, :default => "encrypt"
    config_param :jwk_file, :string, :default => "key"
    config_param :jwk_pub_file, :string, :default => "key.pub"
    config_param :block_cipher_alg, :string, :default => "A128GCM"
    config_param :key_encryption_alg, :string, :default => "RSA1_5"

    def not_supported_error
      $log.error "JwtFilter: Not supported method is specified"
    end

    # This method is called after config_params have read configuration parameters
    def configure(conf)
      super
      begin
        case @method
        when "encrypt"
          # read public key from file
          @jwk_pub = JSON::JWK.new(JSON.parse(open(@jwk_pub_file).read))
        when "decrypt"
          # read private key from file
          @jwk = JSON::JWK.new(JSON.parse(open(@jwk_file).read))
        else
          not_supported_error
        end
      rescue JSON::ParserError => e
        $log.error "JSON Web Key parse error", :error => e.to_s
        $log.debug_backtrace(e.backtrace)
      end
    end

    def start
      super
    end

    def shutdown
      super
    end

    def filter(tag, time, record)
      case @method
      when "encrypt"
        encrypt(record)
      when "decrypt"
        decrypt(record)
      else
        not_supported_error
      end
    end

    # This is the method that formats the data output.
    def encrypt(record)
      begin
        # encrypt JSON format record
        jwe = JSON::JWE.new(record.to_json)
        # choose block cipher algorithm
        jwe.enc = @block_cipher_alg.to_sym
        # choose cipher algorithm for encrypting block cipher key (symmetric cipher key)
        jwe.alg = @key_encryption_alg.to_sym
        # encryption
        jwe.encrypt!(@jwk_pub.to_key)
        # output the result in JSON format
        output = {jwe_encrypted: jwe.as_json}
        $log.debug output
        output
      rescue Exception => e
        $log.error "Error", :error => e.to_s
        $log.debug_backtrace(e.backtrace)
      end
    end

    def decrypt(record)
      begin
        # decrypt JSON format cipher data
        jwe_dec = JSON::JWE.decode_json_serialized(record["jwe_encrypted"], @jwk.to_key)
        $log.debug jwe_dec.plain_text
        # merge decrypted contents into original contents without jwe_encrypted
        output = record.select {|k| k != "jwe_encrypted"}.merge(JSON.parse(jwe_dec.plain_text))
        $log.debug output
        output
      rescue JSON::ParserError => e
        $log.error "Message parse error", :error => e.to_s
        $log.debug_backtrace(e.backtrace)
      rescue Exception => e
        $log.error "Error", :error => e.to_s
        $log.debug_backtrace(e.backtrace)
      end
    end
  end
end
