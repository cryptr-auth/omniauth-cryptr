# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Cryptr < OmniAuth::Strategies::OAuth2
      option :name, 'cryptr'
      option :pkce, true

      def request_call
        options.authorize_params[:state] = state = SecureRandom.hex(24)
        request_params = request.params
        locale = request_params['locale'] || 'en'
        session['omniauth.locale'] = locale

        client_options = options.client_options
        client_options[:authorize_url] = '/'

        super
      end

      def authorize_params
        if OmniAuth.config.test_mode
          @env ||= {}
          @env['rack.session'] ||= {}
        end

        session['omniauth.nonce'] = nonce = SecureRandom.hex

        params = options.authorize_params
                        .merge(options_for('authorize'))
                        .merge(pkce_authorize_params)
                        .merge({ nonce: nonce })

        email = request.params['email']
        if email.present?
          params = params.merge({ email: email })
        end

        org_domain = request.params['org_domain']
        if org_domain.present?
          params = params.merge({ domain: org_domain, org_domain: org_domain })
        end

        params = params.merge({
          locale: session['omniauth.locale'],
          client_state: params[:state]
        })

        session['omniauth.pkce.verifier'] = options.pkce_verifier if options.pkce
        session['omniauth.state']         = params[:state]

        params
      end

      def callback_phase
        request_params   = request.params
        state            = request_params['state']
        authorization_id = request_params['authorization_id']
        request_id       = request_params['request_id']
        client_options   = options.client_options
        client_id        = options.client_id
        tenant           = request.params['organization_domain'] || client_options.tenant
        nonce            = session['omniauth.nonce']

        client_options[:token_url] = "/org/#{tenant}/oauth2/token?nonce=#{nonce}&request_id=#{request_id}&client_id=#{client_id}&authorization_id=#{authorization_id}&client_state=#{state}" unless tenant.nil? || client_id.nil? || authorization_id.nil? || state.nil?

        super
      end

      # Build a hash of information about the user
      # with keys taken from the Auth Hash Schema.
      info do
        {
          name:       raw_info['name'] || raw_info['given_name'] || raw_info['sub'],
          email:      raw_info['email'],
          nickname:   raw_info['nickname'],
          first_name: raw_info['first_name'],
          last_name:  raw_info['last_name'],
          location:   raw_info['zoneinfo'],
          # description: ,
          image:      raw_info['picture'],
          # phone: ,
          urls:       []
        }
      end

      extra { { raw_info: raw_info } }

      uid { raw_info['sub'] }

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      def other_phase
        access_token = request.params['token']

        if access_token.present? && on_logout_path?
          client_options = options.client_options
          site = client_options.site
          tenant = JWT.decode(access_token, nil, false)[0]['tnt'] || client_options.tenant
          client_id = options.client_id

          request_params = {
            token: access_token,
            token_type_hint: 'access_token'
          }

          response =  client
                      .request(:post, "#{site}/api/v1/tenants/#{tenant}/#{client_id}/oauth/token/revoke", params: request_params)
                      .response

          if response.success?
            slo_code = JSON.parse(response.body)['slo_code']

            aud = JWT.decode(access_token, nil, false)[0]['aud'] || request.base_url

            if slo_code
              session['omniauth.slo_url'] =
                "#{site}/api/v1/tenants/#{tenant}/#{client_id}/oauth/token/slo-after-revoke-token?slo_code=#{slo_code}&target_url=#{aud}"
            end
          end

          call_app!
        else
          call_app!
        end
      end
  
      def logout_path
        options[:logout_path] || '/auth/cryptr/logout'
      end

      def on_logout_path?
        on_path?(logout_path)
      end
      
      protected

      def raw_info
        return @raw_info if @raw_info

        if access_token['id_token']
          session['omniauth.credentials'] = credentials
          claims, header = jwt_decode(access_token['id_token'])
          @raw_info = claims
        else
          userinfo_url = options.client_options.userinfo_url
          @raw_info = access_token.get(userinfo_url).parsed
        end

        return @raw_info
      end

      # Decodes a JWT and verifies it's signature. Only tokens signed with the RS256 or HS256 signatures are supported.
      # @param jwt string - JWT to verify.
      # @return hash - The decoded token, if there were no exceptions.
      # @see https://github.com/jwt/ruby-jwt
      def jwt_decode(jwt)
        tnt = JWT.decode(jwt, nil, false)[0]['tnt']

        JWT.decode(jwt, nil, true, decode_opts('RS256', tnt)) do |header|
          jwks_hash(tnt)[header['kid']]
        end
      end

      # Get the JWT decode options. We disable the claim checks since we perform our claim validation logic
      # Docs: https://github.com/jwt/ruby-jwt
      # @return hash
      def decode_opts(alg, tnt)
        opts = {
          algorithm:         alg,
          iss:               issuer(tnt),
          verify_expiration: true,
          verify_iat:        true,
          verify_iss:        true,
          verify_aud:        true,
          verify_sub:        true,
          verify_not_before: true
        }

        opts.merge!({ aud: options.client_options[:audience] }) if options.client_options[:audience].present?
        opts.merge!({ verify_jti: options.client_options[:verify_jti] }) if options.client_options[:verify_jti].present?
        opts
      end
      
      def jwks_hash(tnt)
        uri = jwks_uri(tnt)
        req = Net::HTTP::Get.new(uri.request_uri)

        res = Net::HTTP.start(
                uri.host, uri.port,
                :use_ssl => uri.scheme == 'https'
              ) do |https|
          https.request(req)
        end

        jwks_raw = res.body
        jwks_keys = Array(JSON.parse(jwks_raw)['keys'])

        Hash[
          jwks_keys
          .map do |k|
            [
              k['kid'],
              OpenSSL::X509::Certificate.new(
                Base64.decode64(k['x5c'].first)
              ).public_key
            ]
          end
        ]
      end
    
      def issuer(tnt)
        "#{options.client_options.site}/t/#{tnt}"
      end
      
      def jwks_uri(tnt)
        URI("#{issuer(tnt)}/.well-known/jwks")
      end
    end
  end
end
