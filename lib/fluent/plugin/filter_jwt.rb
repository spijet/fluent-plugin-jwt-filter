# frozen_string_literal: true

require 'jwt'

module Fluent
  module Plugin
    # JwtFilter
    # (Un)pack JSON message using JSON Web Token Technology
    #
    # This module only works with simple JWT tokens (i.e. no fancy RSA inside).
    #
    class JwtFilter < Filter
      # Register this filter as "jwt"
      Fluent::Plugin.register_filter('jwt', self)

      params = { up: { m: %i[field merge replace record], v: %i[no mark warn] },
                 pc: { m: %i[record fields one_field] } }

      supported_hmacs = %i[HS256 HS384 HS512]

      # Common params
      config_param :mode, :enum, list: %i[pack unpack]
      config_param :secret, :string, default: nil, secret: true

      # Unpacking options
      config_param :unpack_mode, :enum, list: params[:up][:m], default: :field
      config_param :unpack_from_field, :string, default: 'jwt'
      config_param :unpack_to_field, :string, default: 'jwt_unpacked'
      config_param :unpack_fields, :array, default: [], value_type: :string
      config_param :unpack_verify, :enum, list: params[:up][:v], default: :no

      # Packing options
      config_param :pack_hmac, :enum, list: supported_hmacs, default: :HS256
      config_param :pack_mode, :enum, list: params[:pc][:m], default: :record
      config_param :pack_fields, :array, default: [], value_type: :string
      config_param :pack_from_field, :string, default: nil
      config_param :pack_to_field, :string, default: 'jwt_packed'
      config_param :pack_remove_source, :bool, default: false

      def hash_pick(hash, *keys)
        common_keys = keys & hash.keys
        Hash[common_keys.map { |key| [key, hash[key]] }]
      end

      def not_supported_error
        log.error 'JwtFilter: Unknown method is specified.'
      end

      # This method is called after config_params have read configuration params
      def configure(conf)
        log.debug "JwtFilter: Loaded with these params: \"#{conf}\"."
        super

        case @mode
        when :pack
          log.error 'JwtFilter: Set a HMAC secret to pack JWTs.' if @secret.nil?

          if @pack_mode == :one_field && @pack_from_field.nil?
            log.error 'JwtFilter: Please specify the field you want to pack.'
          elsif @pack_mode == :fields && @pack_fields.empty?
            log.error 'JwtFilter: Please specify the fields you want to pack.'
          end
        when :unpack
          if @unpack_verify != :no && @secret.to_s.empty?
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

      def filter(_tag, _time, record)
        case @mode
        when :pack   then pack(record)
        when :unpack then unpack(record)
        else not_supported_error
        end
      end

      def source_fields(record)
        case @pack_mode
        when :record    then record
        when :fields    then hash_pick(records, @pack_fields)
        when :one_field then record[@pack_from_field]
        end
      end

      def filter_fields(record)
        return record unless @pack_remove_source

        case @pack_mode
        when :record    then {}
        when :fields    then rec.reject { |f| @pack_fields.include? f }
        when :one_field then rec.reject { |f| f == @pack_from_field }
        end
      end

      # This is the method that formats the data output.
      def pack(record)
        # Pack fields to JSON Web Token, using specified HMAC and secret
        fields = source_fields(record)
        jwt_field = {
          @pack_to_field => JWT.encode(fields, @secret, @pack_hmac)
        }

        output = filter_fields(record).merge(jwt_field)
        log.debug output
        output
      rescue StandardError => e
        log.error 'Error', error: e.to_s
        log.debug_backtrace(e.backtrace)
      end

      def jwt_unpack(message, secret = nil, verify = false)
        valid = true
        out = begin
                JWT.decode message, secret, verify
              rescue JWT::VerificationError
                valid = false
                JWT.decode message, nil, false
              end
        { out: out, valid: valid }
      end

      def extract_fields(message)
        out = if @unpack_fields.empty?
                message[:out].first
              else
                hash_pick(message[:out].first, *@unpack_fields)
              end
        out.merge('jwt_valid' => message[:valid])
      end

      def unpack_to(record, fields)
        case @unpack_mode
        when :field
          record.merge(@unpack_to_field => fields)
        when :merge
          record.merge(fields)
        when :replace
          record.merge(@unpack_from_field => fields)
        when :record
          fields
        end
      end

      def unpack(record)
        return record unless record.key? @unpack_from_field

        msg_raw = record[@unpack_from_field]
        log.debug format('JwtFilter: This is what I got from the message ' \
                         '[field "%<field>s"]: "%<msg>s".',
                         field: @unpack_from_field, msg: msg_raw)

        msg_dec = jwt_unpack(msg_raw, @secret, (@unpack_verify != :no))
        log.debug format('JwtFilter: Unpacked JWT: "%<jwt>s"', jwt: msg_dec)

        if @unpack_verify == :warn && msg_dec[:valid] == false
          log.warn format(<<~WARN_EOL, secret: @secret, msg: @msg_raw)
            JwtFilter: Message signature [secret "%<secret>s"] is invalid: "%<msg>s".
          WARN_EOL
        end

        output = unpack_to(record, extract_fields(msg_dec))
        log.debug format('JwtFilter: Final record: "%<out>s".', out: output)

        output
      rescue JSON::ParserError => e
        log.error 'Message parse error', error: e.to_s
        log.debug_backtrace(e.backtrace)
      rescue StandardError => e
        log.error 'Error', error: e.to_s
        log.debug_backtrace(e.backtrace)
      end
    end
  end
end
