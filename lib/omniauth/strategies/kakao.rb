require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Kakao < OmniAuth::Strategies::OAuth2
      option :name, 'kakao'

      option :client_options, {
        site: 'https://kauth.kakao.com',
        authorize_path: '/oauth/authorize',
        token_url: '/oauth/token',
      }

      uid { raw_info['id'].to_s }

      extra do
        { raw_info: raw_info }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      private

      def raw_info
        @raw_info ||= access_token.get('https://kapi.kakao.com/v2/user/me').parsed
      end

      def raw_kakao_account
        @raw_kakao_account ||= raw_info['kakao_account']
      end
    end
  end
end

OmniAuth.config.add_camelization 'kakao', 'Kakao'
