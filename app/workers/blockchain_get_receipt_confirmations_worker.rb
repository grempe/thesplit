class BlockchainGetReceiptConfirmationsWorker
  include Sidekiq::Worker

  # Retrieve and store all ready Blockchain Receipt confirmations.
  # A confirmation is when the Merkle tree root of a receipt
  # is actually visible on a third party blockchain viewer
  # as a confirmed transaction.
  def perform
    unless ENV['TIERION_ENABLED']
      logger.info('Exiting. TIERION_ENABLED is false or not set. No-Op')
      return nil
    end

    $redis.smembers('blockchain:receipt_confirmations_pending_queue').each do |server_hash_id|
      # find the receipt contents if it exists
      receipt_json = $redis.hget("blockchain:id:#{server_hash_id}", 'receipt')

      # instantiate a new Receipt
      if receipt_json.present?
        receipt_hash = JSON.parse(receipt_json)
        receipt = Tierion::HashApi::Receipt.new(receipt_hash)
      end

      # check for confirmations
      if receipt.valid?
        confirmations = receipt.confirmations
      else
        raise "Stored receipt for server_hash_id '#{server_hash_id}' is invalid"
      end

      next unless confirmations.present? && confirmations['BTCOpReturn']

      # store the confirmation alongside the hash item receipt
      # store the timestamp it was confirmed as the value
      $redis.hset("blockchain:id:#{server_hash_id}", 'confirmed', Time.now.utc.iso8601)

      # remove this ID from the confirmation queue
      $redis.srem('blockchain:receipt_confirmations_pending_queue', server_hash_id)
    end
  end
end
