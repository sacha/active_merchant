require 'rexml/document'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class SlimcdGateway < Gateway
      API_VERSION = "0.1"
      API_PRODUCT = "ActiveMerchant"

      class_inheritable_accessor :test_url, :live_url, :duplicate_window

      self.test_url = 'https://stats.slimcd.com/wswebservices/transact.asmx/PostXML'
      self.live_url = 'https://stats.slimcd.com/wswebservices/transact.asmx/PostXML'
      
      self.duplicate_window = 30

      # We deal with dollars
      self.money_format = :dollars
      
      # The countries the gateway supports merchants from as 2 digit ISO country codes
      self.supported_countries = ['US']
      
      # The card types supported by the payment gateway
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]
      
      # The homepage URL of the gateway
      self.homepage_url = 'http://www.slimcd.com/'
      
      # The name of the gateway
      self.display_name = 'SlimCD'
      
      # Creates a new SlimcdGateway
      #
      # The gateway requires that valid credentials be passed
      # in the +options+ hash.
      #
      # ==== Options
      #
      # * <tt>:client_id</tt> -- Assigned by the Slim CD administrator. (REQUIRED)
      # * <tt>:site_id</tt> -- Assigned by the Slim CD administrator. (REQUIRED)
      # * <tt>:price_id</tt> -- Assigned by the Slim CD administrator. (REQUIRED)
      # * <tt>:password</tt> -- Plaintext password for the client account. (REQUIRED)
      # * <tt>:key</tt> -- SDK developer key obtained from Slim CD, Inc. (REQUIRED)
      def initialize(options = {})
        requires!(options, :client_id, :site_id, :price_id, :password, :key)
        @options = options
        super
      end  
      
      # Performs an authorization, which reserves the funds on the customer's credit card, but does not
      # charge the card.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be authorized. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      def authorize(money, creditcard, options = {})
        post = {}
        add_invoice(post, options)
        add_creditcard(post, creditcard)        
        add_address(post, creditcard, options)        
        add_customer_data(post, options)
        add_duplicate_window(post)
        
        commit('AUTH', money, post)
      end
      
      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be purchased. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      def purchase(money, creditcard, options = {})
        post = {}
        add_invoice(post, options)
        add_creditcard(post, creditcard)        
        add_address(post, creditcard, options)   
        add_customer_data(post, options)
        add_duplicate_window(post)
             
        commit('SALE', money, post)
      end                       
    
      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      def capture(money, authorization, options = {})
        post = { :gateid => authorization }
        commit('FORCE', money, post)
      end
    
      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      def void(authorization, options = {})
        post = { :gateid => authorization }
        commit('VOID', nil, post)
      end
    
      # Credit an account.
      #
      # This transaction is also referred to as a Refund and indicates to the gateway that
      # money should flow from the merchant to the customer.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be credited to the customer. Either an Integer value in cents or a Money object.
      # * <tt>identification</tt> -- The ID of the original transaction against which the credit is being issued.
      # * <tt>options</tt> -- A hash of parameters.
      #
      # ==== Options
      #
      # * <tt>:card_number</tt> -- The credit card number the credit is being issued to. (REQUIRED)
      def credit(money, identification, options = {})
        post = { :gateid => identification }

        commit('CREDIT', money, post)
      end
    
    
      private                       
      
      def add_customer_data(post, options)
        if options.has_key? :email
          post[:email] = options[:email]
        end
        
        if options.has_key? :ip
          post[:clientip] = options[:ip]
        end
        
      end

      def add_address(post, creditcard, options)  
        address = options[:billing_address] || options[:address]
        
        unless address.nil?
          post[:address] = address[:address1].to_s
          post[:city] = address[:city].to_s
          post[:state] = address[:state].to_s
          post[:zip] = address[:zip].to_s
          post[:country] = address[:country].to_s
          post[:phone] = address[:phone].to_s
        end
      end

      def add_invoice(post, options)
        post[:client_transref] = options[:order_id] || options[:invoice] || options[:description] || options[:customer]
      end
      
      def add_creditcard(post, creditcard)  
        post[:cardnumber] = creditcard.number
        post[:CVV2] = creditcard.verification_value if creditcard.verification_value?
        post[:expmonth] = creditcard.month
        post[:expyear] = creditcard.year
        post[:first_name] = creditcard.first_name
        post[:last_name] = creditcard.last_name  
      end
      
      def add_duplicate_window(post)
        if duplicate_window.nil?
          post[:allow_duplicates] = 'yes'
        else
          post[:allow_duplicates] = 'no'
          post[:duplicates_window] = duplicate_window
        end
      end
      
      def parse(body)
        response = {:description => "Response Parse Error"}
        xml = REXML::Document.new(CGI.unescape(body.chomp))
        xml.elements.each('//reply/*') do |node|
          response[node.name.downcase.to_sym] = normalize(node.text) unless node.name.downcase == 'datablock'
        end unless xml.root.nil?
        xml.elements.each('//reply/datablock/*') do |node|
          response[node.name.downcase.to_sym] = normalize(node.text)
        end unless xml.root.nil?
        response
      end     

      # Make a ruby type out of the response string
      def normalize(field)
        case field
        when "true"   then true
        when "false"  then false
        when ""       then nil
        when "null"   then nil
        else field
        end
      end

      def commit(action, money, parameters)
        parameters[:amount] = amount(money) unless action == 'VOID'
        
        url = test? ? self.test_url : self.live_url
        data = ssl_post url, post_data(action, parameters)
        
        response = parse(data)
        
        message = message_from(response)
        
        Response.new(success?(response), message, response,
          :test => false,
          :avs_result => { :code => response[:avsreply] },
          :cvv_result => response[:cvv2reply],
          :authorization => response[:gateid],
          :fraud_review => fraud_review?(response)
        )
      end

      def success?(response)
        response[:response] == "Success" && (response[:approved] == "Y" || response[:approved] == "B")
      end
      
      def fraud_review?(response)
        response[:authcode] == "D"
      end

      def message_from(response)
        response[:description]
      end
      
      def post_data(action, parameters = {})
        parameters[:transtype] = action
                
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request' do
          request = parameters.each { |key, value| xml.tag! key, value }
        end
        posthash = { :XMLData => xml.target!, 
          :clientid => @options[:client_id], 
          :siteid => @options[:site_id], 
          :priceid => @options[:price_id],
          :password => @options[:password],
          :key => @options[:key],
          :ver => API_VERSION,
          :product => API_PRODUCT
        }
        posthash.collect { |key,value| "#{key}=#{CGI.escape(value.to_s)}"}.join("&")
      end
    end
  end
end
