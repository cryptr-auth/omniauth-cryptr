# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Cryptr < OmniAuth::Strategies::OAuth2
      option :name, 'cryptr'
      option :pkce, true

      def request_call
        request_params   = request.params
        idp_id = request_params['idp_id']

        options.authorize_params[:state] = state = SecureRandom.hex(24)

        client_options = options.client_options
        client_options[:authorize_url] =
          if idp_id
            session['omniauth.idp_id'] = idp_id
            session['omniauth.sign_type'] = 'sso'
            "/enterprise/#{idp_id}/login"
          else
            tenant    = client_options.tenant
            locale    = request_params['locale'] || 'en'
            sign_type = session['omniauth.sign_type'] = request_params['sign_type'] || 'signin'

            "/t/#{tenant}/#{locale}/#{state}/#{sign_type}/new"
          end

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

        session['omniauth.pkce.verifier'] = options.pkce_verifier if options.pkce
        session['omniauth.state']         = params[:state]

        params
      end

      def callback_phase
        request_params   = request.params
        state            = request_params['state']
        authorization_id = request_params['authorization_id']

        client_id      = options.client_id
        client_options = options.client_options
        tenant         = client_options.tenant

        sign_type = session['omniauth.sign_type']
        nonce     = session['omniauth.nonce']

        client_options[:token_url] =
          "/api/v1/tenants/#{tenant}/#{client_id}/#{state}/oauth/#{sign_type}/client/#{authorization_id}/token?nonce=#{nonce}" unless
            state.nil? || authorization_id.nil? || tenant.nil? || client_id.nil?

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

      def other_phase
        access_token = request.params['token']

        if access_token.present? && on_logout_path?
          client_options = options.client_options
          site = client_options.site
          tenant = client_options.tenant
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

            if slo_code
              session['omniauth.slo_url'] =
                "#{site}/api/v1/tenants/#{tenant}/#{client_id}/oauth/token/slo-after-revoke-token?slo_code=#{slo_code}&target_url=#{'http://localhost:3000'}"
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
        JWT.decode(jwt, nil, false, decode_opts('S256'))
      end

      # Get the JWT decode options. We disable the claim checks since we perform our claim validation logic
      # Docs: https://github.com/jwt/ruby-jwt
      # @return hash
      def decode_opts(alg)
        {
          algorithm:         alg,
          verify_expiration: true,
          verify_iat:        true,
          verify_iss:        true,
          verify_aud:        true,
          verify_jti:        true,
          verify_subj:       true,
          verify_not_before: true
        }
      end
    end
  end
end
