require 'fdk'
require 'oci/common'
require 'oci/auth/auth'
require 'oci/core/core'
require 'oci/object_storage/object_storage'
require 'oci/loggingingestion/loggingingestion'
require 'json'
require 'uri'
require 'net/http'
require 'openssl'
require 'date'
require 'base64'
require 'securerandom'

VT_API_KEY = ENV['VT_API_KEY']
OCI_LOG_ID = ENV['OCI_LOG_OCID']
QUARANTINE_THRESHOLD = ENV['QUARANTINE_THRESHOLD'].to_i
DELETE_THRESHOLD = ENV['DELETE_THRESHOLD'].to_i
QUARANTINE_BUCKET_REGION = ENV['QUARANTINE_BUCKET_REGION']
QUARANTINE_BUCKET_NAME = ENV['QUARANTINE_BUCKET_NAME']
ON_ERROR = ENV['ON_ERROR']
EXCLUDE_BUCKETS = ENV['EXCLUDE_BUCKETS'].nil? ? [] : ENV['EXCLUDE_BUCKETS'].split(',')

# Returns the signer, for the SDK to auth calls to the tenancy
def get_signer
  begin
    session_token = ENV['OCI_RESOURCE_PRINCIPAL_RPST']
    private_key = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM']
    private_key_passphrase = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM_PASSPHRASE']
    region = ENV['OCI_RESOURCE_PRINCIPAL_REGION']
    return OCI::Auth::Signers::EphemeralResourcePrincipalsSigner.new(
      session_token: session_token,
      private_key: private_key,
      private_key_passphrase: private_key_passphrase,
      region: region
    )
  rescue Exception => e
    FDK.log(entry: e.to_s)
  end
end


# Entry point for the OCI Function
def check_file(context:, input:)

  if EXCLUDE_BUCKETS.include?(input['data']['additionalDetails']['bucketName'])
    FDK.log(entry: "Skipping #{input['data']['resourceName']} as it resides in excluded bucket #{input['data']['additionalDetails']['bucketName']}")
    return
  end

  object_storage_client = OCI::ObjectStorage::ObjectStorageClient.new(signer: get_signer)
  FDK.log(entry: "Checking file #{input['data']['resourceName']}")
  object_info = object_storage_client.head_object(input['data']['additionalDetails']['namespace'], input['data']['additionalDetails']['bucketName'], URI::Parser.new.escape(input['data']['resourceName']))
  file_hex_md5 = Base64.decode64(object_info.headers['content-md5']).unpack('H*').first
  FDK.log(entry: "Checking Virus Total #{input['data']['resourceName']} / #{file_hex_md5}")

  vt_response = check_virus_total(file_hex_md5)
  vt_response.merge!(os_namespace: input['data']['additionalDetails']['namespace'],
                     bucket_name: input['data']['additionalDetails']['bucketName'],
                     object_name: input['data']['resourceName'],
                     file_type: object_info.headers['content-type'],
                     md5_hash: file_hex_md5,
                     file_size: object_info.headers['content-length'])

  if vt_response[:scan_result] == 'Error'
    case ON_ERROR
    when 'QUARANTINE'
      FDK.log(entry: "QUARANTINING: #{input['data']['resourceName']}, as error occurred")
      quarantine_object(input['data']['additionalDetails']['namespace'], input['data']['additionalDetails']['bucketName'], input['data']['resourceName'])
      vt_response.merge!(av_action: 'Quarantined')
    when 'DELETE'
      FDK.log(entry: "DELETING: #{input['data']['resourceName']}, as error occurred")
      delete_object(input['data']['additionalDetails']['namespace'], input['data']['additionalDetails']['bucketName'], input['data']['resourceName'])
      vt_response.merge!(av_action: 'Deleted')
    end

  else #then the VT AI response
    if !vt_response[:confidence].nil?
      if vt_response[:confidence] >= DELETE_THRESHOLD
        FDK.log(entry: "DELETING: #{input['data']['resourceName']}, confidence #{vt_response[:confidence]} above delete threshold #{DELETE_THRESHOLD} ")
        delete_object(input['data']['additionalDetails']['namespace'], input['data']['additionalDetails']['bucketName'], input['data']['resourceName'])
        vt_response.merge!(av_action: 'Deleted')
      elsif vt_response[:confidence] >= QUARANTINE_THRESHOLD
        FDK.log(entry: "QUARANTINING: #{input['data']['resourceName']}, confidence #{vt_response[:confidence]} above quarantine threshold #{QUARANTINE_THRESHOLD} ")
        quarantine_object(input['data']['additionalDetails']['namespace'], input['data']['additionalDetails']['bucketName'], input['data']['resourceName'])
        vt_response.merge!(av_action: 'Quarantined')
      end
    else
      FDK.log(entry: "File #{input['data']['resourceName']} not flagged as malicious")
      vt_response.merge!(av_action: nil)
    end
  end

  log_av_scan(vt_response)
end



# Copies the file to the quarantine bucket, and deletes it from the source bucket.
def quarantine_object(os_namespace, source_bucket, object_name)
  object_storage_client= OCI::ObjectStorage::ObjectStorageClient.new(signer: get_signer)
  copy_object_response = object_storage_client.copy_object(
    os_namespace,
    source_bucket,
    OCI::ObjectStorage::Models::CopyObjectDetails.new(
      source_object_name: URI::Parser.new.escape(object_name),
      destination_region: QUARANTINE_BUCKET_REGION,
      destination_namespace: os_namespace,
      destination_bucket: QUARANTINE_BUCKET_NAME,
      destination_object_name: URI::Parser.new.escape(object_name),
      destination_object_storage_tier: 'Standard'
    )
  )
  sleep(30) #we need to wait until the copy request has completed
  delete_object(os_namespace, source_bucket, object_name)
end

# Deletes the malicious file from the source bucket.
def delete_object(os_namespace, source_bucket, object_name)
  object_storage_client= OCI::ObjectStorage::ObjectStorageClient.new(signer: get_signer)
  delete_object_response = object_storage_client.delete_object(
      os_namespace,
      source_bucket,
      URI::Parser.new.escape(object_name)
    )
end

# Pushes the Scan Results to Logging
def log_av_scan(scan_response)
  log_time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')

  loggingingestion_client = OCI::Loggingingestion::LoggingClient.new(signer: get_signer)
    loggingingestion_client.put_logs(
      OCI_LOG_ID,
      OCI::Loggingingestion::Models::PutLogsDetails.new(
        specversion: '1.0',
        log_entry_batches: [
          OCI::Loggingingestion::Models::LogEntryBatch.new(
            entries: [
              OCI::Loggingingestion::Models::LogEntry.new(
                data: scan_response.to_json,
                id: "ocid1.av-scanner.oc1..#{SecureRandom.uuid}",
                time: log_time
              )
            ],
            source: 'os-av-scanner',
            type: 'os-av-scanner',
            defaultlogentrytime: log_time,
            subject: 'Object AV Scan Results'
          )
        ]
      )
    )
end

# Search Virus Total for the Bucket Object MD5 hash.
def check_virus_total(query_term)
  url = URI("https://www.virustotal.com/api/v3/search?query=#{query_term}")
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  request = Net::HTTP::Get.new(url)
  request["Accept"] = 'application/json'
  request["x-apikey"] = VT_API_KEY
  response = http.request(request)
  FDK.log(entry: "Virus Total returned #{response.code} for search #{query_term}")
  return {category: nil,
          name: nil,
          positive_signals: nil,
          negative_signals: nil,
          confidence: nil,
          scan_result: 'Error',
          message: response.code == "429" ?  'Virus Total API Limit Exceeded' : 'Virus Total Error',
          av_link: nil } if response.code != "200"

  vt_response = JSON.parse(response.read_body)
  if !vt_response['data'].empty?
    malware_category = vt_response['data'][0]['attributes']['type_description']
    if vt_response['data'][0]['attributes']['popular_threat_classification'].nil?
      threat_name = vt_response['data'][0]['attributes']['meaningful_name']
    else
      threat_name = vt_response['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label']
    end
    positive_signals = vt_response['data'][0]['attributes']['last_analysis_stats']['malicious']
    negative_signals = vt_response['data'][0]['attributes']['last_analysis_stats']['undetected']
    url_link = "https://www.virustotal.com/gui/search/#{vt_response['links']['self'][vt_response['links']['self'].index('=')+1..-1]}"
    return {category: malware_category,
            name: threat_name,
            positive_signals: positive_signals,
            negative_signals: negative_signals,
            confidence: ((positive_signals.to_f / (positive_signals + negative_signals).to_f) * 100).round(0),
            scan_result: ((positive_signals.to_f / (positive_signals + negative_signals).to_f) * 100).round(0) >= QUARANTINE_THRESHOLD ? 'Fail' : 'Pass',
            message: 'Virus Total API Lookup Succeeded',
            av_link: url_link }
  else #theres nothing in VT for this file hash
    return {category: nil,
            name: nil,
            positive_signals: nil,
            negative_signals: nil,
            confidence: nil,
            scan_result: 'Pass',
            message: 'Virtus Total API Lookup returned no results',
            av_link: nil }
  end
end

FDK.handle(target: :check_file)