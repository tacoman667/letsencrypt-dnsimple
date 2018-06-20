require "openssl"
require "shellwords"

require "dnsimple"
require "acme-client"
require "dotenv"

Dotenv.load

cert_file_path = ''
is_staging = false

while not ARGV.empty?
  if ARGV.first.start_with?("-")
    case ARGV.shift  # shift takes the first argument and removes it from the array
    when '--staging', '-s'
      DEFAULT_LETSENCRYPT_ENDPOINT = "https://acme-staging-v02.api.letsencrypt.org/directory"
      is_staging = true
    when '--path', '-p'
      cert_file_path = ARGV.shift
      cert_file_path = "#{cert_file_path}/" unless cert_file_path.empty? or cert_file_path[-1] == '/'
    end
  end
end

cert_file_path = "#{cert_file_path}staging/" if is_staging

DEFAULT_LETSENCRYPT_ENDPOINT ||= "https://acme-v02.api.letsencrypt.org/directory"
DNSIMPLE_TTL = 60

puts "Using #{DEFAULT_LETSENCRYPT_ENDPOINT}"

raw_names = ENV.fetch("NAMES").split(",")
authorize_names = raw_names.inject({}) {|h, rn| n = rn.sub("/", "."); d = rn.split("/", 2).last; h.update(n => d) }

# dnsimple = Dnsimple::Client.new(username: ENV.fetch("DNSIMPLE_API_USER"), api_token: ENV.fetch("DNSIMPLE_API_TOKEN"))
dnsimple = Dnsimple::Client.new(access_token: ENV.fetch("DNSIMPLE_ACCESS_TOKEN"))
dnsimple_account_id = dnsimple.identity.whoami.data.account.id

private_key = OpenSSL::PKey::RSA.new(4096)
client = Acme::Client.new(private_key: private_key, directory: ENV.fetch("LETSENCRYPT_ENDPOINT", DEFAULT_LETSENCRYPT_ENDPOINT))
account = client.new_account(contact: "mailto:#{ENV.fetch("ACME_CONTACT")}", terms_of_service_agreed: true)

order = client.new_order(identifiers: authorize_names.collect { |k,v| k })

order.authorizations.each do |authorization|
  dns_challenge = authorization.dns

  # dns_challenge.record_name # => '_acme-challenge'
  # dns_challenge.record_type # => 'TXT'
  # dns_challenge.record_content # => 'HRV3PS5sRDyV-ous4HJk4z24s5JjmUTjcCaUjFt28-8'

  # full name to authorize
  letsencrypt_authorize_name = "#{dns_challenge.record_name}.#{authorization.domain}"
  # the name we care about at dnsimple
  dnsimple_authorize_name = letsencrypt_authorize_name.sub(/(\A|\.)#{Regexp.escape(authorize_names.values.first)}\z/, "")

  puts "preparing to authorize #{authorization.domain} via #{letsencrypt_authorize_name} with dnsimple record #{dnsimple_authorize_name}/#{authorize_names.values.first}"

  # dnsimple.zones.all_records(dnsimple_account_id, authorize_names.values.first).data.select do |record|
  #   record.name == dnsimple_authorize_name && record.type == dns_challenge.record_type
  # end.each do |existing_record|
  #   puts "deleting existing record: #{existing_record.id} #{existing_record.name} #{existing_record.type} #{existing_record.content}"
  #   dnsimple.zones.delete_record(dnsimple_account_id, authorize_names.values.first, existing_record.id)
  # end

  puts "creating new record: #{dnsimple_authorize_name} (#{authorize_names.values.first}) #{dns_challenge.record_type} #{dns_challenge.record_content}"

  new_record = dnsimple.zones.create_record(
    dnsimple_account_id,
    authorize_names.values.first,
    name: dnsimple_authorize_name,
    type: dns_challenge.record_type,
    content: dns_challenge.record_content,
    ttl: DNSIMPLE_TTL)


  puts "waiting for record to be at dnsimple servers"
  loop do
    system("dig @ns1.dnsimple.com #{Shellwords.escape(letsencrypt_authorize_name)} txt | grep -e #{Shellwords.escape(dns_challenge.record_content)}")
    break if $?.success?
    sleep 5
  end

  dns_challenge.request_validation
  while dns_challenge.status == 'pending'
    sleep(2)
    dns_challenge.reload
  end

  # cleanup dns
  dnsimple.zones.delete_record(dnsimple_account_id, authorize_names.values.first, new_record.data.id)
end

filename_base = authorize_names.values.first

private_key_for_csr = OpenSSL::PKey::RSA.new(4096)
csr = Acme::Client::CertificateRequest.new(names: authorize_names.keys)

order.finalize(csr: csr)
sleep(1) while order.status == 'processing'

# make the directory unless it alredy exists or was not defined in args
Dir.mkdir cert_file_path unless cert_file_path.empty? or Dir.exist?(cert_file_path)

puts "Writing certificates to #{Dir.pwd}/#{cert_file_path}"

File.write("#{cert_file_path}#{filename_base}-privkey.pem", csr.private_key.to_pem)
# File.write("#{cert_file_path}#{filename_base}-cert.pem", certificate.to_pem)
# File.write("#{cert_file_path}#{filename_base}-chain.pem", certificate.chain_to_pem)
File.write("#{cert_file_path}#{filename_base}-fullchain.pem", order.certificate)

puts "Done writing certificates"