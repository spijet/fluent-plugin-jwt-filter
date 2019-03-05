require 'jwt'
module Fluent::Plugin
  # JwtFilter
  # (Un)pack JSON message using JSON Web Token Technology
  #
  # This module only works with simple JWT tokens (i.e. no fancy RSA inside).
  #
  class JwtFilter < Filter
    # Register this filter as "jwt"
    Fluent::Plugin.register_filter('jwt', self)

    unp_to_list = %i[field merge replace record]
    unp_ve_list = %i[no mark discard]
    supported_hmacs = %i[HS256 HS384 HS512]

    # Common params
    config_param :method, :enum, list: %i[pack unpack]
    config_param :hmac_secret, :string, default: nil, secret: true

    # Unpacking options
    config_param :unpack_from_field, :string, default: 'jwt'
    config_param :unpack_to, :enum, list: unp_to_list, default: :field
    config_param :unpack_to_field, :string, default: 'jwt_unpacked'
    config_param :unpack_fields, :array, default: [], value_type: :string
    config_param :unpack_verify, :enum, list: unp_ve_list, default: :no

    # Packing options
    config_param :pack_from, :enum, list: %[record fields one_field], default: :record
    config_param :pack_from_field, :string, default: nil
    config_param :pack_fields, :array, default: [], value_type: :string
    config_param :pack_to, :enum, list: %i[field replace record], default: :field
    config_param :pack_to_field, :string, default: 'jwt_packed'
    config_param :pack_hmac, :enum, list: supported_hmacs, default: :HS256

    def hash_pick(hash, *keys)
      common_keys = keys & hash.keys
      values = hash.values_at(*common_keys)
      Hash[common_keys.map{ |key| [key, hash[key]] }]
    end

    def not_supported_error
      log.error 'JwtFilter: Unknown method is specified.'
    end

    # This method is called after config_params have read configuration params
    def configure(conf)
      super

      begin
        case @method
        when :pack
          if @hmac_secret.nil?
            log.error 'JwtFilter: Cannot pack JWT tokens without a HMAC secret.'
          end
          if @pack_from == :one_field && @pack_from_field.nil?
            log.error 'JwtFilter: Please specify which field you want to pack.'
          end
          if @pack_from == :fields && @pack_fields.empty?
            log.error 'JwtFilter: Please specify which fields you want to pack.'
          end
          if @pack_from == :record && @pack_to == :replace
            log.warn <<-EOW
              JwtFilter: Replace-packing the whole record is the same as packing to record.
              Consider setting "pack_to" to "record".
            EOW
          end
        when :unpack
          if %i[mark discard].include?(@verify) && @hmac_secret.nil?
            log.error 'JwtFilter: Cannot verify records without a secret.'
          end
        else
          not_supported_error
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
      when :pack
        pack(record)
      when :unpack
        unpack_and_extract(record)
      else
        not_supported_error
      end
    end

    # This is the method that formats the data output.
    def pack(record)
      begin
        fields_to_pack = case @pack_from
                         when :record
                           record
                         when :one_field
                           record[@pack_from_field]
                         when :field
                           hash_pick(records, @pack_fields)
                         end

        # Pack fields to JSON Web Token, using specified HMAC and secret
        jwt = {
          @pack_to_field => JWT.encode(fields_to_pack, @hmac_secret, @pack_hmac)
        }

        output = case @pack_to
                 when :field
                   record.merge({ @pack_to_field => jwt })
                 when :replace
                   pre_out = record.reject { |field| fields_to_pack.key? field }
                   pre_out.merge({ @pack_to_field => jwt })
                 when :record
                   { @pack_to_field => jwt }
                 end
        log.debug output
        output
      rescue Exception => e
        log.error "Error", error: e.to_s
        log.debug_backtrace(e.backtrace)
      end
    end

    def unpack(message, secret: nil, verify: false)
      valid = true
      out = if verify
              begin
                JWT.decode message, secret, true
              rescue JWT::VerificationError
                valid = false
                JWT.decode message, nil, false
              end
            else
              JWT.decode message, nil, false
            end
      {out: out, valid: valid}
    end

    def extract(message, fields = @unpack_fields)
      out = if fields.count > 0
              hash_pick(message[:out].first, *fields)
            else
              message[:out].first
            end
      out.merge({'jwt_valid' => message[:valid]})
    end

    def unpack_and_extract(record)
      begin
        message = record[@unpack_from_field]
        message_dec = unpack(message, @hmac_secret, (@verify != :no))
        log.debug message_dec

        if @verify != :no && message_dec[:valid] == false
          log.warn 'Message signature is invalid:' + message.inspect
          return nil if @verify == :discard
        end

        pre_out = extract(message, @unpack_fields)
        output = case @unpack_to
                 when :field
                   record.merge({ @unpack_to_field => pre_out })
                 when :merge
                   record.merge(pre_out)
                 when :replace
                   record.merge({ @unpack_from_field => pre_out })
                 when :record
                   pre_out
                 end

        log.debug output
        output
      rescue JSON::ParserError => e
        log.error "Message parse error", error: e.to_s
        log.debug_backtrace(e.backtrace)
      rescue Exception => e
        log.error "Error", error: e.to_s
        log.debug_backtrace(e.backtrace)
      end
    end
  end
end
