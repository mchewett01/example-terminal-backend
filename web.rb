require 'sinatra'
require 'stripe'
require 'dotenv'
require 'json'
require 'sinatra/cross_origin'
require 'rack/utils'
require 'base64'
require 'digest'
require 'tempfile'
require 'time'

# Browsers require that external servers enable CORS when the server is at a different origin than the website.
# https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
# This enables the requires CORS headers to allow the browser to make the requests from the JS Example App.
configure do
  enable :cross_origin
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
end

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token, X-POS-PIN"
  response.headers["Access-Control-Allow-Origin"] = "*"
  200
end

Dotenv.load
Stripe.api_key = ENV['STRIPE_ENV'] == 'production' ? ENV['STRIPE_SECRET_KEY'] : ENV['STRIPE_TEST_SECRET_KEY']
Stripe.api_version = '2020-03-02'

def log_info(message)
  puts "\n" + message + "\n\n"
  return message
end

# --- Hewett POS transaction history / returns helpers -----------------------

POS_AUTH_MAX_FAILURES = 5
POS_AUTH_WINDOW_SECONDS = 10 * 60
POS_AUTH_LOCKOUT_SECONDS = 15 * 60
POS_AUTH_FAILURES = {}

def json_response(payload, status_code = 200)
  content_type :json
  status status_code
  payload.to_json
end

# Validate receipt emails before they are sent to Stripe. The Android app
# performs the same check for user experience, but the backend remains the
# final guard so malformed receipt_email values can never reach Stripe.
def valid_receipt_email?(email)
  normalized = email.to_s.strip
  return false if normalized.empty?
  return false if normalized.length > 254

  !!(normalized =~ /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
end

def request_ip_address
  request.ip.to_s
end

def cleanup_pos_auth_failures!
  now = Time.now.to_i

  POS_AUTH_FAILURES.delete_if do |_ip, record|
    last_failure = record[:last_failure].to_i
    locked_until = record[:locked_until].to_i

    locked_until <= now &&
      last_failure > 0 &&
      now - last_failure > POS_AUTH_WINDOW_SECONDS
  end
end

def pos_auth_record
  cleanup_pos_auth_failures!

  POS_AUTH_FAILURES[request_ip_address] ||= {
    failures: [],
    last_failure: 0,
    locked_until: 0
  }
end

def pos_auth_locked?
  pos_auth_record[:locked_until].to_i > Time.now.to_i
end

def record_pos_auth_failure!
  now = Time.now.to_i
  record = pos_auth_record

  recent_failures =
    record[:failures]
      .select { |timestamp| now - timestamp < POS_AUTH_WINDOW_SECONDS }

  recent_failures << now

  record[:failures] = recent_failures
  record[:last_failure] = now

  if recent_failures.length >= POS_AUTH_MAX_FAILURES
    record[:locked_until] = now + POS_AUTH_LOCKOUT_SECONDS
  end
end

def clear_pos_auth_failures!
  POS_AUTH_FAILURES.delete(request_ip_address)
end

def pos_admin_pin
  ENV['POS_ADMIN_PIN'].to_s
end

def pos_authorized?
  expected = pos_admin_pin
  provided = request.env['HTTP_X_POS_PIN'].to_s

  return false if expected.empty? || provided.empty?
  return false unless expected.bytesize == provided.bytesize

  Rack::Utils.secure_compare(expected, provided)
end

def require_pos_authorization!
  if pos_admin_pin.empty?
    halt 503, json_response(
      {
        :error =>
          "POS_ADMIN_PIN is not configured on the backend."
      },
      503
    )
  end

  if pos_auth_locked?
    halt 429, json_response(
      {
        :error =>
          "Too many incorrect PIN attempts. Try again in 15 minutes."
      },
      429
    )
  end

  if !pos_authorized?
    record_pos_auth_failure!

    halt 401, json_response(
      { :error => "Invalid admin PIN." },
      401
    )
  end

  clear_pos_auth_failures!
end

def successful_charge_from_payment_intent(payment_intent)
  return nil if payment_intent.nil?
  return nil if payment_intent.charges.nil?
  return nil if payment_intent.charges.data.nil?
  return nil if payment_intent.charges.data.empty?

  payment_intent.charges.data.find do |charge|
    charge.status.to_s == 'succeeded'
  end || payment_intent.charges.data.first
end

def full_charge_for_payment_intent(payment_intent)
  charge = successful_charge_from_payment_intent(payment_intent)
  return nil if charge.nil?

  # When PaymentIntent.list expands the Charge, all fields we need are
  # already present. When a PaymentIntent is retrieved without expansion,
  # retrieve the Charge directly to ensure amount_refunded and
  # balance_transaction are current.
  if !charge.balance_transaction.nil?
    return charge
  end

  Stripe::Charge.retrieve(charge.id)
end

def terminal_payment_intent?(payment_intent)
  payment_method_types =
    payment_intent.payment_method_types || []

  return true if payment_method_types.include?('card_present')

  charge = successful_charge_from_payment_intent(payment_intent)
  return false if charge.nil?
  return false if charge.payment_method_details.nil?

  charge.payment_method_details.type.to_s == 'card_present'
end

def emulator_test_payment_intent?(payment_intent)
  return false if payment_intent.nil?
  return false if payment_intent.metadata.nil?

  payment_intent.metadata['hewett_pos_emulator_test'].to_s == 'true'
end

def pos_payment_intent?(payment_intent)
  terminal_payment_intent?(payment_intent) ||
    emulator_test_payment_intent?(payment_intent)
end

def processing_fee_cents(charge)
  return nil if charge.nil?

  balance_transaction = charge.balance_transaction
  return nil if balance_transaction.nil?

  if !balance_transaction.is_a?(String)
    return balance_transaction.fee.to_i
  end

  Stripe::BalanceTransaction
    .retrieve(balance_transaction)
    .fee
    .to_i
end

def payment_customer_email(payment_intent, charge)
  receipt_email = payment_intent.receipt_email.to_s
  return receipt_email if !receipt_email.empty?

  return nil if charge.nil?
  return nil if charge.billing_details.nil?

  email = charge.billing_details.email.to_s
  email.empty? ? nil : email
end


def customer_for_receipt(email, name = nil)
  normalized_email = email.to_s.strip
  return nil if normalized_email.empty?

  existing = Stripe::Customer.list(
    :email => normalized_email,
    :limit => 1
  ).data.first

  if !existing.nil?
    normalized_name = name.to_s.strip

    if existing.name.to_s.strip.empty? && !normalized_name.empty?
      existing = Stripe::Customer.update(
        existing.id,
        :name => normalized_name
      )
    end

    return existing
  end

  customer_params = {
    :email => normalized_email
  }

  normalized_name = name.to_s.strip
  customer_params[:name] = normalized_name if !normalized_name.empty?

  Stripe::Customer.create(customer_params)
end

def payment_metadata(payment_intent)
  return {} if payment_intent.nil?

  metadata = payment_intent.metadata
  return {} if metadata.nil?

  raw_metadata =
    if metadata.respond_to?(:to_hash)
      metadata.to_hash
    else
      metadata
    end

  # Stripe::StripeObject#to_hash can yield symbol keys depending on the
  # stripe-ruby object/version. The POS metadata written by this app is
  # referenced everywhere else with string keys ("item_count",
  # "item_0", etc.), so normalize every key here. Without this, a
  # transaction can clearly contain item metadata in Stripe while the
  # item-return parser sees an empty cart.
  normalized = {}

  raw_metadata.each do |key, value|
    normalized[key.to_s] = value.to_s
  end

  normalized
end

# Extracts POS metadata from an Android form request in a way that is robust
# across Rack/Sinatra parsing behavior. The Android app sends every value in
# two forms:
#
#   metadata[item_count]=2
#   pos_meta_item_count=2
#
# The explicit pos_meta_ fields are authoritative. We retain support for the
# nested and literal bracketed forms for backwards compatibility.
def extract_pos_metadata(request_params)
  metadata = {}

  nested =
    request_params['metadata'] ||
    request_params[:metadata]

  if nested.respond_to?(:each)
    nested.each do |key, value|
      metadata[key.to_s] = value.to_s
    end
  end

  request_params.each do |key, value|
    key_string = key.to_s

    if key_string.start_with?('pos_meta_')
      metadata_key = key_string.sub('pos_meta_', '')
      metadata[metadata_key] = value.to_s
      next
    end

    match = key_string.match(/\Ametadata\[(.+)\]\z/)
    if !match.nil?
      metadata[match[1]] ||= value.to_s
    end
  end

  metadata
end

def metadata_integer(payment_intent, key)
  payment_metadata(payment_intent)[key.to_s].to_i
end

def parse_pos_items(payment_intent)
  metadata = payment_metadata(payment_intent)
  count = metadata['item_count'].to_i

  return [] if count <= 0

  items = []

  count.times do |index|
    raw = metadata["item_#{index}"].to_s
    next if raw.empty?

    parts = raw.split('~', 3)
    next if parts.length < 3

    item_id = parts[0].to_s
    list_price = parts[1].to_i
    item_name = parts[2].to_s

    next if item_id.empty? || list_price <= 0

    items << {
      :id => item_id,
      :name => item_name.empty? ? item_id : item_name,
      :listPriceCents => list_price
    }
  end

  items
end

def proportional_allocations(total, weights)
  total = total.to_i
  weights = weights.map(&:to_i)
  weight_total = weights.sum

  return Array.new(weights.length, 0) if total <= 0 || weight_total <= 0

  allocations = []
  remainders = []

  weights.each_with_index do |weight, index|
    numerator = total * weight
    quotient, remainder = numerator.divmod(weight_total)

    allocations << quotient
    remainders << [remainder, index]
  end

  cents_left = total - allocations.sum

  remainders
    .sort_by { |remainder, index| [-remainder, index] }
    .first(cents_left)
    .each do |_remainder, index|
      allocations[index] += 1
    end

  allocations
end

def allocated_pos_items(payment_intent)
  items = parse_pos_items(payment_intent)
  return [] if items.empty?

  weights = items.map { |item| item[:listPriceCents].to_i }
  subtotal_total = metadata_integer(payment_intent, 'subtotal_cents')
  tax_total = metadata_integer(payment_intent, 'tax_cents')

  subtotal_allocations =
    proportional_allocations(subtotal_total, weights)

  tax_allocations =
    proportional_allocations(tax_total, weights)

  items.each_with_index.map do |item, index|
    subtotal = subtotal_allocations[index].to_i
    tax = tax_allocations[index].to_i

    item.merge(
      :allocatedSubtotalCents => subtotal,
      :allocatedTaxCents => tax,
      :grossReturnValueCents => subtotal + tax
    )
  end
end

def refunds_for_charge(charge)
  return [] if charge.nil?

  Stripe::Refund.list(
    :charge => charge.id,
    :limit => 100
  ).data
end

def pos_refund_state(payment_intent, charge)
  gross_return_value_used = 0
  restocking_fee_retained = 0
  shipping_refunded = 0
  returned_item_ids = []
  tracked_refund_amount = 0

  refunds_for_charge(charge).each do |refund|
    refund_status = refund.status.to_s
    next if refund_status == 'failed' || refund_status == 'canceled'

    tracked_refund_amount += refund.amount.to_i

    raw_metadata =
      if refund.metadata.nil?
        {}
      elsif refund.metadata.respond_to?(:to_hash)
        refund.metadata.to_hash
      else
        refund.metadata
      end

    # Normalize refund metadata keys exactly as we do PaymentIntent metadata.
    # stripe-ruby can return symbol keys from StripeObject#to_hash. Without
    # normalization, returned_item_ids is missed and an already-returned
    # painting can incorrectly appear available for another return.
    metadata = {}
    raw_metadata.each do |key, value|
      metadata[key.to_s] = value.to_s
    end

    retained_fee =
      if metadata['restocking_fee_retained_cents'].to_s.empty?
        metadata['restocking_fee_cents'].to_i
      else
        metadata['restocking_fee_retained_cents'].to_i
      end

    gross_value =
      if metadata['gross_return_value_cents'].to_s.empty?
        refund.amount.to_i + retained_fee
      else
        metadata['gross_return_value_cents'].to_i
      end

    gross_return_value_used += gross_value
    restocking_fee_retained += retained_fee
    shipping_refunded += metadata['shipping_refunded_cents'].to_i

    item_ids =
      metadata['returned_item_ids']
        .to_s
        .split(',')
        .map(&:strip)
        .reject(&:empty?)

    returned_item_ids.concat(item_ids)
  end

  # If a refund was issued directly in Stripe rather than through the POS,
  # include it in the used return value so the app can never over-refund.
  untracked_refund =
    [charge.amount_refunded.to_i - tracked_refund_amount, 0].max

  gross_return_value_used += untracked_refund

  {
    :gross_return_value_used => gross_return_value_used,
    :restocking_fee_retained => restocking_fee_retained,
    :shipping_refunded => shipping_refunded,
    :returned_item_ids => returned_item_ids.uniq
  }
end

def transaction_payload(payment_intent)
  charge = full_charge_for_payment_intent(payment_intent)
  return nil if charge.nil?

  amount = charge.amount.to_i
  amount_refunded = charge.amount_refunded.to_i
  fee = processing_fee_cents(charge)
  refund_state = pos_refund_state(payment_intent, charge)

  if fee.nil?
    maximum_policy_refund = 0
    remaining_policy_refund = 0
    transaction_status = 'fee_pending'
    fee_for_payload = 0
  else
    maximum_policy_refund = [amount - fee, 0].max
    remaining_policy_refund =
      [maximum_policy_refund - amount_refunded, 0].max
    fee_for_payload = fee

    transaction_status =
      if amount_refunded >= amount
        'refunded'
      elsif amount_refunded.positive?
        'partially_refunded'
      else
        payment_intent.status.to_s
      end
  end

  returned_item_ids = refund_state[:returned_item_ids]

  items =
    allocated_pos_items(payment_intent).map do |item|
      item.merge(
        :returned => returned_item_ids.include?(item[:id])
      )
    end

  shipping = metadata_integer(payment_intent, 'shipping_cents')
  shipping_refunded =
    [refund_state[:shipping_refunded].to_i, shipping].min

  {
    :paymentIntentId => payment_intent.id,
    :created => payment_intent.created.to_i,
    :description => payment_intent.description,
    :customerEmail => payment_customer_email(payment_intent, charge),
    :amountCents => amount,
    :amountRefundedCents => amount_refunded,
    :processingFeeCents => fee_for_payload,
    :remainingPolicyRefundCents => remaining_policy_refund,
    :currency => charge.currency.to_s,
    :status => transaction_status,
    :listPriceCents => metadata_integer(payment_intent, 'list_price_cents'),
    :discountCents => metadata_integer(payment_intent, 'discount_cents'),
    :subtotalCents => metadata_integer(payment_intent, 'subtotal_cents'),
    :taxCents => metadata_integer(payment_intent, 'tax_cents'),
    :shippingCents => shipping,
    :shippingRefundedCents => shipping_refunded,
    :restockingFeeRetainedCents =>
      refund_state[:restocking_fee_retained].to_i,
    :grossReturnValueUsedCents =>
      refund_state[:gross_return_value_used].to_i,
    :items => items
  }
end

def build_refund_quote(
  payment_intent,
  mode,
  requested_item_ids = [],
  include_shipping = false,
  custom_gross_cents = 0
)
  if payment_intent.status.to_s != 'succeeded'
    raise ArgumentError,
      'Only successful captured payments can be refunded.'
  end

  if !pos_payment_intent?(payment_intent)
    raise ArgumentError,
      'This payment was not created by the Hewett POS app.'
  end

  charge = full_charge_for_payment_intent(payment_intent)

  if charge.nil?
    raise ArgumentError,
      'No successful charge was found for this payment.'
  end

  original_amount = charge.amount.to_i
  processing_fee = processing_fee_cents(charge)

  if processing_fee.nil?
    raise RuntimeError,
      'Stripe has not made the processing fee available yet. Try again shortly.'
  end

  refund_state = pos_refund_state(payment_intent, charge)
  gross_used = refund_state[:gross_return_value_used].to_i
  fee_retained_so_far = refund_state[:restocking_fee_retained].to_i
  returned_item_ids = refund_state[:returned_item_ids]

  remaining_gross = [original_amount - gross_used, 0].max

  if remaining_gross <= 0
    raise ArgumentError,
      'No additional return value is available for this transaction.'
  end

  items = allocated_pos_items(payment_intent)
  available_items =
    items.reject { |item| returned_item_ids.include?(item[:id]) }

  shipping_total = metadata_integer(payment_intent, 'shipping_cents')
  shipping_refunded_so_far =
    [refund_state[:shipping_refunded].to_i, shipping_total].min
  remaining_shipping =
    [shipping_total - shipping_refunded_so_far, 0].max

  selected_item_ids = []
  shipping_refund = 0
  gross_return_value = 0

  case mode.to_s
  when 'items'
    if items.empty?
      raise ArgumentError,
        'Item-level return details are not available for this older transaction.'
    end

    requested = requested_item_ids.map(&:to_s).uniq

    if requested.empty?
      raise ArgumentError,
        'Select at least one painting to return.'
    end

    already_returned =
      requested.select { |item_id| returned_item_ids.include?(item_id) }

    if !already_returned.empty?
      raise ArgumentError,
        'One or more selected paintings have already been returned.'
    end

    known_item_ids = items.map { |item| item[:id].to_s }
    unknown_items = requested.reject { |item_id| known_item_ids.include?(item_id) }

    if !unknown_items.empty?
      raise ArgumentError,
        'One or more selected paintings are not part of this transaction.'
    end

    selected_items =
      available_items.select { |item| requested.include?(item[:id]) }

    if selected_items.length != requested.length
      raise ArgumentError,
        'One or more selected paintings are not available to return.'
    end

    selected_item_ids = selected_items.map { |item| item[:id] }
    gross_return_value =
      selected_items.sum { |item| item[:grossReturnValueCents].to_i }

    if include_shipping && remaining_shipping > 0
      shipping_refund = remaining_shipping
      gross_return_value += shipping_refund
    end

    if gross_return_value <= 0
      raise ArgumentError,
        'Select at least one painting or remaining shipping charge.'
    end

  when 'custom'
    gross_return_value = custom_gross_cents.to_i

    if gross_return_value <= 0
      raise ArgumentError,
        'A positive custom return value is required.'
    end

  when 'full'
    gross_return_value = remaining_gross
    selected_item_ids = available_items.map { |item| item[:id] }
    shipping_refund = remaining_shipping

  else
    raise ArgumentError,
      'Unknown refund mode.'
  end

  if gross_return_value > remaining_gross
    raise ArgumentError,
      'That return exceeds the remaining refundable value of this transaction.'
  end

  cumulative_gross = gross_used + gross_return_value

  target_cumulative_fee =
    if original_amount <= 0
      0
    else
      (
        processing_fee * cumulative_gross +
        original_amount / 2
      ) / original_amount
    end

  target_cumulative_fee =
    [target_cumulative_fee, processing_fee].min

  restocking_fee_this_refund =
    [target_cumulative_fee - fee_retained_so_far, 0].max

  restocking_fee_this_refund =
    [restocking_fee_this_refund, gross_return_value].min

  refund_amount =
    gross_return_value - restocking_fee_this_refund

  if refund_amount <= 0
    raise ArgumentError,
      'The calculated customer refund is zero.'
  end

  {
    :paymentIntentId => payment_intent.id,
    :preview => true,
    :mode => mode.to_s,
    :grossReturnValueCents => gross_return_value,
    :refundAmountCents => refund_amount,
    :processingFeeCents => processing_fee,
    :restockingFeeThisRefundCents => restocking_fee_this_refund,
    :restockingFeeRetainedCents =>
      fee_retained_so_far + restocking_fee_this_refund,
    :amountRefundedCents => charge.amount_refunded.to_i,
    :shippingRefundCents => shipping_refund,
    :returnedItemIds => selected_item_ids,
    :status => 'preview',
    :charge => charge
  }
end


get '/' do
  status 200
  send_file 'index.html'
end

def validateApiKey
  if Stripe.api_key.nil? || Stripe.api_key.empty?
    return "Error: you provided an empty secret key. Please provide your test mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('pk')
    return "Error: you used a publishable key to set up the example backend. Please use your test mode secret key. For more information, see https://stripe.com/docs/keys"
  end
  if Stripe.api_key.start_with?('sk_live')
    return "Error: you used a live mode secret key to set up the example backend. Please use your test mode secret key. For more information, see https://stripe.com/docs/keys#test-live-modes"
  end
  return nil
end

# This endpoint registers a Verifone P400 reader to your Stripe account.
# https://stripe.com/docs/terminal/readers/connecting/verifone-p400#register-reader
post '/register_reader' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    reader = Stripe::Terminal::Reader.create(
      :registration_code => params[:registration_code],
      :label => params[:label],
      :location => params[:location]
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error registering reader! #{e.message}")
  end

  log_info("Reader registered: #{reader.id}")

  status 200
  # Note that returning the Stripe reader object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return reader.to_json
end

# This endpoint creates a ConnectionToken, which gives the SDK permission
# to use a reader with your Stripe account.
# https://stripe.com/docs/terminal/sdk/js#connection-token
# https://stripe.com/docs/terminal/sdk/ios#connection-token
# https://stripe.com/docs/terminal/sdk/android#connection-token
#
# The example backend does not currently support connected accounts.
# To create a ConnectionToken for a connected account, see
# https://stripe.com/docs/terminal/features/connect#direct-connection-tokens
post '/connection_token' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    token = Stripe::Terminal::ConnectionToken.create
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating ConnectionToken! #{e.message}")
  end

  content_type :json
  status 200
  return {:secret => token.secret}.to_json
end

# This endpoint creates a PaymentIntent.
# https://stripe.com/docs/terminal/payments#create
#
# The example backend does not currently support connected accounts.
# To create a PaymentIntent for a connected account, see
# https://stripe.com/docs/terminal/features/connect#direct-payment-intents-server-side
post '/create_payment_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    receipt_email = params[:receipt_email].to_s.strip

    if !receipt_email.empty? && !valid_receipt_email?(receipt_email)
      status 400
      return log_info("Invalid receipt email address.")
    end

    metadata = extract_pos_metadata(params)
    log_info("POS payment metadata item_count=#{metadata['item_count']} keys=#{metadata.keys.sort.join(',')}")
    customer_name = metadata['customer_name'].to_s

    customer = customer_for_receipt(
      receipt_email,
      customer_name
    )

    payment_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
      :capture_method => params[:capture_method] || 'manual',
      :amount => params[:amount],
      :currency => params[:currency] || 'usd',
      :description => params[:description] || 'Example PaymentIntent',
      :payment_method_options => params[:payment_method_options] || [],
      :metadata => metadata
    }

    if !receipt_email.empty?
      payment_intent_params[:receipt_email] = receipt_email
    end

    if !customer.nil?
      payment_intent_params[:customer] = customer.id
    end

    payment_intent = Stripe::PaymentIntent.create(
      payment_intent_params
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully created: #{payment_intent.id}")
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end


# Uploads the customer's handwritten signature to Stripe Files before the
# PaymentIntent is created. Only a real PNG image is accepted. The returned
# Stripe File ID, SHA-256 digest, and server-side signing timestamp are then
# written to the PaymentIntent metadata by the Android app.
#
# Stripe's dedicated customer_signature file purpose is used so the signature
# remains inside the same Stripe account as the payment rather than on the
# Render filesystem.
post '/upload_signature' do
  validationError = validateApiKey
  if !validationError.nil?
    return json_response({ :error => validationError }, 400)
  end

  encoded = params[:signature_base64].to_s.strip

  if encoded.empty?
    return json_response(
      { :error => 'A customer signature is required.' },
      400
    )
  end

  if encoded.start_with?('data:image/png;base64,')
    encoded = encoded.sub('data:image/png;base64,', '')
  end

  begin
    bytes = Base64.strict_decode64(encoded)
  rescue ArgumentError
    return json_response(
      { :error => 'The customer signature image is invalid.' },
      400
    )
  end

  if bytes.empty?
    return json_response(
      { :error => 'The customer signature image is empty.' },
      400
    )
  end

  # Stripe permits customer_signature files up to 4 MB. Reject oversized
  # payloads here before writing anything to disk or calling Stripe.
  if bytes.bytesize > 4 * 1024 * 1024
    return json_response(
      { :error => 'The customer signature image is too large.' },
      400
    )
  end

  png_magic = "\x89PNG\r\n\x1A\n".b

  if bytes.byteslice(0, 8) != png_magic
    return json_response(
      { :error => 'Only PNG customer signatures are accepted.' },
      400
    )
  end

  sha256 = Digest::SHA256.hexdigest(bytes)
  signed_at = Time.now.utc.iso8601

  begin
    uploaded_file = nil

    Tempfile.create(['hewett-pos-signature-', '.png']) do |tempfile|
      tempfile.binmode
      tempfile.write(bytes)
      tempfile.flush

      uploaded_file = Stripe::File.create(
        {
          :purpose => 'customer_signature',
          :file => File.new(tempfile.path)
        }
      )
    end

    log_info(
      "Customer signature uploaded: #{uploaded_file.id} sha256=#{sha256}"
    )

    return json_response(
      {
        :signatureFileId => uploaded_file.id,
        :sha256 => sha256,
        :signedAt => signed_at
      },
      200
    )
  rescue Stripe::StripeError => e
    return json_response(
      { :error => "Unable to save customer signature: #{e.message}" },
      402
    )
  rescue StandardError => e
    return json_response(
      { :error => "Unable to save customer signature: #{e.message}" },
      500
    )
  end
end


# Creates a genuine Stripe TEST-mode card payment for Android emulator testing.
#
# The emulator cannot present a physical card to the Terminal SDK, so this
# endpoint uses Stripe's standard test Visa PaymentMethod and immediately
# confirms the PaymentIntent. The resulting payment is tagged in metadata so
# the POS transaction-history screen can include it alongside real
# card-present S710 payments.
#
# This endpoint intentionally refuses to run with a live secret key.
post '/create_emulator_test_payment' do
  validationError = validateApiKey
  if !validationError.nil?
    return json_response({ :error => validationError }, 400)
  end

  if !Stripe.api_key.to_s.start_with?('sk_test')
    return json_response(
      { :error => 'Emulator test payments are disabled outside Stripe test mode.' },
      403
    )
  end

  amount = params[:amount].to_i

  if amount <= 0
    return json_response(
      { :error => 'A positive payment amount is required.' },
      400
    )
  end

  metadata = extract_pos_metadata(params)
  metadata['hewett_pos'] = 'true'
  metadata['hewett_pos_emulator_test'] = 'true'
  metadata['source'] = 'android_emulator'

  log_info("POS emulator metadata item_count=#{metadata['item_count']} keys=#{metadata.keys.sort.join(',')}")

  begin
    receipt_email = params[:receipt_email].to_s.strip

    if !receipt_email.empty? && !valid_receipt_email?(receipt_email)
      return json_response(
        { :error => 'Enter a valid receipt email address.' },
        400
      )
    end

    customer = customer_for_receipt(
      receipt_email,
      metadata['customer_name']
    )

    payment_intent_params = {
      :amount => amount,
      :currency => params[:currency] || 'usd',
      :payment_method_types => ['card'],
      :payment_method => 'pm_card_visa',
      :confirm => true,
      :description => params[:description] || 'Hewett POS emulator test payment',
      :metadata => metadata
    }

    if !receipt_email.empty?
      payment_intent_params[:receipt_email] = receipt_email
    end

    if !customer.nil?
      payment_intent_params[:customer] = customer.id
    end

    payment_intent = Stripe::PaymentIntent.create(
      payment_intent_params
    )
  rescue Stripe::StripeError => e
    return json_response(
      { :error => "Error creating emulator test payment: #{e.message}" },
      402
    )
  end

  log_info("Emulator test PaymentIntent successfully created: #{payment_intent.id}")

  json_response(
    {
      :intent => payment_intent.id,
      :secret => payment_intent.client_secret
    },
    200
  )
end


# This endpoint captures a PaymentIntent.
# https://stripe.com/docs/terminal/payments#capture
post '/capture_payment_intent' do
  begin
    id = params["payment_intent_id"]
    if !params["amount_to_capture"].nil?
      payment_intent = Stripe::PaymentIntent.capture(id, :amount_to_capture => params["amount_to_capture"])
    else
      payment_intent = Stripe::PaymentIntent.capture(id)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error capturing PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully captured: #{id}")
  # Optionally reconcile the PaymentIntent with your internal order system.
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint cancels a PaymentIntent.
# https://stripe.com/docs/api/payment_intents/cancel
post '/cancel_payment_intent' do
  begin
    id = params["payment_intent_id"]
    payment_intent = Stripe::PaymentIntent.cancel(id)
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error canceling PaymentIntent! #{e.message}")
  end

  log_info("PaymentIntent successfully canceled: #{id}")
  # Optionally reconcile the PaymentIntent with your internal order system.
  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end

# This endpoint creates a SetupIntent.
# https://stripe.com/docs/api/setup_intents/create
post '/create_setup_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    setup_intent_params = {
      :payment_method_types => params[:payment_method_types] || ['card_present'],
    }

    if !params[:customer].nil?
      setup_intent_params[:customer] = params[:customer]
    end

    if !params[:description].nil?
      setup_intent_params[:description] = params[:description]
    end

    if !params[:on_behalf_of].nil?
      setup_intent_params[:on_behalf_of] = params[:on_behalf_of]
    end

    setup_intent = Stripe::SetupIntent.create(setup_intent_params)

  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating SetupIntent! #{e.message}")
  end

  log_info("SetupIntent successfully created: #{setup_intent.id}")
  status 200
  return {:intent => setup_intent.id, :secret => setup_intent.client_secret}.to_json
end

# Looks up or creates a Customer on your stripe account
# with email "example@test.com".
def lookupOrCreateExampleCustomer
  customerEmail = "example@test.com"
  begin
    customerList = Stripe::Customer.list(email: customerEmail, limit: 1).data
    if (customerList.length == 1)
      return customerList[0]
    else
      return Stripe::Customer.create(email: customerEmail)
    end
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating or retreiving customer! #{e.message}")
  end
end

# This endpoint attaches a PaymentMethod to a Customer.
# https://stripe.com/docs/terminal/payments/saving-cards#read-reusable-card
post '/attach_payment_method_to_customer' do
  begin
    customer = lookupOrCreateExampleCustomer

    payment_method = Stripe::PaymentMethod.attach(
      params[:payment_method_id],
      {
        customer: customer.id,
        expand: ["customer"],
    })
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error attaching PaymentMethod to Customer! #{e.message}")
  end

  log_info("Attached PaymentMethod to Customer: #{customer.id}")

  status 200
  # Note that returning the Stripe payment_method object directly creates a dependency between your
  # backend's Stripe.api_version and your clients, making future upgrades more complicated.
  # All clients must also be ready for backwards-compatible changes at any time:
  # https://stripe.com/docs/upgrades#what-changes-does-stripe-consider-to-be-backwards-compatible
  return payment_method.to_json
end

# This endpoint updates the PaymentIntent represented by 'payment_intent_id'.
# It currently only supports updating the 'receipt_email' property.
#
# https://stripe.com/docs/api/payment_intents/update
post '/update_payment_intent' do
  payment_intent_id = params["payment_intent_id"]
  if payment_intent_id.nil?
    status 400
    return log_info("'payment_intent_id' is a required parameter")
  end

  begin
    allowed_keys = ["receipt_email"]
    update_params = params.select { |k, _| allowed_keys.include?(k) }

    if update_params.key?("receipt_email")
      receipt_email = update_params["receipt_email"].to_s.strip

      if !receipt_email.empty? && !valid_receipt_email?(receipt_email)
        status 400
        return log_info("Invalid receipt email address.")
      end

      update_params["receipt_email"] = receipt_email
    end

    payment_intent = Stripe::PaymentIntent.update(
      payment_intent_id,
      update_params
    )

    log_info("Updated PaymentIntent #{payment_intent_id}")
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error updating PaymentIntent #{payment_intent_id}. #{e.message}")
  end

  status 200
  return {:intent => payment_intent.id, :secret => payment_intent.client_secret}.to_json
end


# This endpoint lists captured Hewett POS payments for the return screen.
# It includes real Stripe Terminal card-present payments plus explicitly tagged
# Android-emulator test payments created by /create_emulator_test_payment.
# It returns the actual Stripe fee from the Charge's balance transaction so the
# app never has to estimate a restocking fee.
#
# The API version used by this sample backend is 2020-03-02, so the Charge and
# its balance transaction are expanded through PaymentIntent.charges.
get '/pos_transactions' do
  validationError = validateApiKey
  if !validationError.nil?
    return json_response({ :error => validationError }, 400)
  end

  require_pos_authorization!

  begin
    payment_intents = Stripe::PaymentIntent.list(
      :limit => 100,
      :expand => ['data.charges.data.balance_transaction']
    )

    transactions =
      payment_intents.data
        .select do |payment_intent|
          payment_intent.status.to_s == 'succeeded' &&
            pos_payment_intent?(payment_intent)
        end
        .map { |payment_intent| transaction_payload(payment_intent) }
        .compact
  rescue Stripe::StripeError => e
    return json_response(
      { :error => "Error fetching transactions: #{e.message}" },
      402
    )
  end

  json_response(transactions, 200)
end

# Calculates a return/refund without changing anything in Stripe.
# The Android app uses this to show the exact customer refund and the
# proportional restocking fee before the operator confirms the return.
post '/preview_refund' do
  validationError = validateApiKey
  if !validationError.nil?
    return json_response({ :error => validationError }, 400)
  end

  require_pos_authorization!

  payment_intent_id = params['payment_intent_id'].to_s

  if payment_intent_id.empty?
    return json_response(
      { :error => 'payment_intent_id is required.' },
      400
    )
  end

  begin
    payment_intent =
      Stripe::PaymentIntent.retrieve(payment_intent_id)

    requested_item_ids =
      params['item_ids']
        .to_s
        .split(',')
        .map(&:strip)
        .reject(&:empty?)

    include_shipping =
      params['include_shipping'].to_s == 'true'

    quote = build_refund_quote(
      payment_intent,
      params['mode'].to_s,
      requested_item_ids,
      include_shipping,
      params['custom_gross_cents'].to_i
    )

    quote.delete(:charge)

    return json_response(quote, 200)
  rescue ArgumentError => e
    return json_response({ :error => e.message }, 400)
  rescue RuntimeError => e
    return json_response({ :error => e.message }, 409)
  rescue Stripe::StripeError => e
    return json_response(
      { :error => "Error calculating refund: #{e.message}" },
      402
    )
  end
end

# Issues either an item-level partial return, a custom partial refund, or a
# full return. The actual original Stripe processing fee is allocated
# proportionally to the cumulative gross value being returned. This means:
#
# - a 35% item return retains about 35% of the original Stripe fee;
# - later partial returns continue from that same cumulative calculation; and
# - if the entire original charge is eventually returned, the total retained
#   restocking fees equal the original Stripe processing fee, never more.
post '/refund_payment_intent' do
  validationError = validateApiKey
  if !validationError.nil?
    return json_response({ :error => validationError }, 400)
  end

  require_pos_authorization!

  payment_intent_id = params['payment_intent_id'].to_s

  if payment_intent_id.empty?
    return json_response(
      { :error => 'payment_intent_id is required.' },
      400
    )
  end

  begin
    payment_intent =
      Stripe::PaymentIntent.retrieve(payment_intent_id)

    requested_item_ids =
      params['item_ids']
        .to_s
        .split(',')
        .map(&:strip)
        .reject(&:empty?)

    include_shipping =
      params['include_shipping'].to_s == 'true'

    quote = build_refund_quote(
      payment_intent,
      params['mode'].to_s,
      requested_item_ids,
      include_shipping,
      params['custom_gross_cents'].to_i
    )

    charge = quote[:charge]

    idempotency_key =
      [
        'hewett-pos-return',
        payment_intent.id,
        charge.amount_refunded.to_i,
        quote[:mode],
        quote[:grossReturnValueCents],
        quote[:returnedItemIds].join('-'),
        quote[:shippingRefundCents]
      ].join('-')

    refund = Stripe::Refund.create(
      {
        :payment_intent => payment_intent.id,
        :amount => quote[:refundAmountCents],
        :reason => 'requested_by_customer',
        :metadata => {
          :hewett_pos_return => 'true',
          :return_mode => quote[:mode],
          :gross_return_value_cents =>
            quote[:grossReturnValueCents].to_s,
          :restocking_fee_retained_cents =>
            quote[:restockingFeeThisRefundCents].to_s,
          :processing_fee_original_cents =>
            quote[:processingFeeCents].to_s,
          :returned_item_ids =>
            quote[:returnedItemIds].join(','),
          :shipping_refunded_cents =>
            quote[:shippingRefundCents].to_s,
          :refund_policy =>
            'proportional_original_stripe_processing_fee'
        }
      },
      {
        :idempotency_key => idempotency_key
      }
    )

    return json_response(
      {
        :refundId => refund.id,
        :paymentIntentId => payment_intent.id,
        :preview => false,
        :mode => quote[:mode],
        :grossReturnValueCents =>
          quote[:grossReturnValueCents],
        :refundAmountCents => refund.amount.to_i,
        :processingFeeCents => quote[:processingFeeCents],
        :restockingFeeThisRefundCents =>
          quote[:restockingFeeThisRefundCents],
        :restockingFeeRetainedCents =>
          quote[:restockingFeeRetainedCents],
        :amountRefundedCents =>
          charge.amount_refunded.to_i + refund.amount.to_i,
        :shippingRefundCents => quote[:shippingRefundCents],
        :returnedItemIds => quote[:returnedItemIds],
        :status => refund.status.to_s
      },
      200
    )
  rescue ArgumentError => e
    return json_response({ :error => e.message }, 400)
  rescue RuntimeError => e
    return json_response({ :error => e.message }, 409)
  rescue Stripe::StripeError => e
    return json_response(
      { :error => "Error issuing refund: #{e.message}" },
      402
    )
  end
end


# This endpoint lists the first 100 Locations. If you will have more than 100
# Locations, you'll likely want to implement pagination in your application so that
# you can efficiently fetch Locations as needed.
# https://stripe.com/docs/api/terminal/locations
get '/list_locations' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    locations = Stripe::Terminal::Location.list(
      limit: 100
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error fetching Locations! #{e.message}")
  end

  log_info("#{locations.data.size} Locations successfully fetched")

  status 200
  content_type :json
  return locations.data.to_json
end

# This endpoint creates a Location.
# https://stripe.com/docs/api/terminal/locations
post '/create_location' do
  validationError = validateApiKey
  if !validationError.nil?
    status 400
    return log_info(validationError)
  end

  begin
    location = Stripe::Terminal::Location.create(
      display_name: params[:display_name],
      address: params[:address]
    )
  rescue Stripe::StripeError => e
    status 402
    return log_info("Error creating Location! #{e.message}")
  end

  log_info("Location successfully created: #{location.id}")

  status 200
  content_type :json
  return location.to_json
end
