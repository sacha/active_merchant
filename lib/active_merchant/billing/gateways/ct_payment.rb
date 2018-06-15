module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class CtPaymentGateway < Gateway
      self.test_url = 'https://test.ctpaiement.ca/v1/'
      self.live_url = 'https://example.com/live'

      self.supported_countries = ['US']
      self.default_currency = 'USD'
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]

      self.homepage_url = 'http://www.example.net/'
      self.display_name = 'CT Payment'

      STANDARD_ERROR_CODE_MAPPING = {}
      CARD_BRAND = {
        'american_express' => 'A',
        'master' => 'M',
        'diners_club' => 'I',
        'visa' => 'V',
        'discover' => 'O'
      }

      def initialize(options={})
        requires!(options, :api_key, :company_number)
        super
      end

      def purchase(money, payment, options={})
        post = {}
        post[:OperatorID] = options[:operator_id] || ' ' * 8
        post[:Amount] = amount(money).rjust(11,'0')
        post[:MerchantTerminalNumber] = options[:merchant_terminal_number]
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        response = (payment.is_a?(String)? commit('purchaseWithToken', post) : commit('purchase', post))
        send_ack(response.authorization)
        response
      end

      def authorize(money, payment, options={})
        post = {}
        post[:OperatorID] = options[:operator_id] || ' ' * 8
        post[:Amount] = amount(money).rjust(11,'0')
        post[:MerchantTerminalNumber] = options[:merchant_terminal_number]
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        response = (payment.is_a?(String)? commit('preAuthorizationWithToken', post) : commit('preAuthorization', post))
        send_ack(response.authorization)
        response
      end

      def capture(money, authorization, options={})
        post = {}
        post[:InvoiceNumber] = options[:order_id]
        post[:Amount] = amount(money).rjust(11,'0')
        add_customer_data(post, options)
        auth = split_authorization(authorization)
        post[:OriginalTransactionNumber] = auth[0]
        post[:OriginalAuthorizationNumber] = auth[1]
        post[:OriginalInvoiceNumber] = auth[2]

        response = commit('completion', post)
        send_ack(response.authorization)
        response
      end

      def refund(money, authorization, options={})
        post = {}
        post[:InvoiceNumber] = options[:order_id]
        post[:Amount] = amount(money).rjust(11,'0')
        add_customer_data(post, options)
        auth = split_authorization(authorization)
        post[:OriginalTransactionNumber] = auth[0]
        post[:OriginalInvoiceNumber] = auth[2]

        response = commit('refundWithoutCard', post)
        send_ack(response.authorization)
        response
      end

      def credit(money, payment, options={})
        post = {}
        post[:OperatorID] = options[:operator_id] || ' ' * 8
        post[:Amount] = amount(money).rjust(11,'0')
        post[:MerchantTerminalNumber] = options[:merchant_terminal_number]
        add_invoice(post, money, options)
        add_payment(post, payment)
        add_address(post, payment, options)
        add_customer_data(post, options)

        response = (payment.is_a?(String)? commit('refundWithToken', post) : commit('refund', post))
        send_ack(response.authorization)
        response
      end

      def void(authorization, options={})
        post = {}
        post['OperatorID'] = options[:operator_id] || ' ' * 8
        post[:InputType] = 'I'
        post[:LanguageCode] = 'E'
        auth = split_authorization(authorization)
        post[:OriginalTransactionNumber] = auth[0]
        post[:OriginalInvoiceNumber] = auth[2]
        add_customer_data(post, options)

        response = commit('void', post)
        send_ack(response.authorization)
        response
      end

      def verify(credit_card, options={})
        post = {}
        post[:MerchantTerminalNumber] = options[:merchant_terminal_number]
        add_invoice(post,0, options)
        add_payment(post, credit_card)
        add_customer_data(post, options)

        response = commit('verifyAccount', post)
        send_ack(response.authorization)
        response
      end

      def store(credit_card, options={})
        post = {}
        post[:OperatorID] = options[:operator_id] || ' ' * 8
        post[:LanguageCode] = 'E'
        post[:Name] = credit_card.name.rjust(50, ' ')
        post[:Email] = options[:email].rjust(240, ' ')
        add_payment(post, credit_card)
        add_customer_data(post, options)

        response = commit('recur/AddUser', post)
        send_ack(response.authorization)
        response
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((&?token:)[^&]*)i, '\1[FILTERED]').
          gsub(%r((&?cardNumber:)[^&]*)i, '\1[FILTERED]')
      end

      private

      def add_customer_data(post, options)
        post[:CustomerNumber] = options[:customer_number] || ' ' * 8
      end

      def add_address(post, creditcard, options)
        if address = options[:billing_address] || options[:address]
          post[:CardHolderAddress] = address[:address1]+address[:city]+address[:state].rjust(20, ' ')
          post[:CardHolderPostalCode] = address[:zip].gsub(/\s+/, "").rjust(9, ' ')
        end
      end

      def add_invoice(post, money,  options)
        post[:CurrencyCode] = options[:currency] || (currency(money) if money)
        post[:InvoiceNumber] = options[:order_id]
        post[:InputType] = 'I'
        post[:LanguageCode] = 'E'
      end

      def add_payment(post, payment)
        if payment.is_a?(String)
          post[:Token] = split_authorization(payment)[3]
        else
          post[:CardType] = CARD_BRAND[payment.brand] || ' '
          post[:CardNumber] = payment.number.rjust(40,' ')
          post[:ExpirationDate] = expdate(payment)
        end
      end

      def send_ack(authorization)
        post = {}
        post[:TransactionNumber] = split_authorization(authorization)[0]
      end

      def parse(body)
        JSON.parse(body)
      end

      def split_authorization(authorization)
        authorization.split(';')
      end

      def commit(action, parameters)
        url = (test? ? test_url : live_url) + action
        response = parse(ssl_post(url, post_data(action, parameters)))

        Response.new(
          success_from(response),
          message_from(response),
          response,
          authorization: authorization_from(response),
          avs_result: AVSResult.new(code: response["some_avs_response_key"]),
          cvv_result: CVVResult.new(response["some_cvv_response_key"]),
          test: test?,
          error_code: error_code_from(response)
        )
      end

      def success_from(response)
        return true if response['returnCode'] = '00'
        return false
      end

      def message_from(response)
        response['errorDescription']
      end

      def authorization_from(response)
        "#{response['transactionNumber']};#{response['authorizationNumber']};#{response['invoiceNumber']};#{response[:token]}"
      end

      def post_data(action, parameters = {})
        parameters['CompanyNumber'] = @options[:company_number]
        parameters['MerchantNumber'] = @options[:merchant_number]
        parameters = parameters.collect { |key, value| "#{key}=#{CGI.escape(value.to_s)}" }.join('&')
        payload = Base64.encode64(parameters)
        "auth-api-key=#{@options[:api_key]}&payload=#{payload}".strip
      end

      def error_code_from(response)
        response['returnCode'] unless success_from(response)
      end
    end
  end
end
