class BlockchainGetReceiptConfirmationsWorker
  include Sidekiq::Worker

  # Retrieve and store all ready Blockchain Receipt confirmations.
  # A confirmation is when the Merkle tree root of a receipt
  # is actually visible on a third-party blockchain viewer
  # as a confirmed transaction.
  def perform
    unless ENV['TIERION_ENABLED'] == 'true'
      logger.info('Exiting. TIERION_ENABLED is not true. No-Op')
      return nil
    end

    $redis.smembers('blockchain:receipt_confirmations_pending_queue').each do |hash|
      # Find the receipt contents if they exist
      receipt_hash = $r.connect($rdb_config) do |conn|
        resp = $r.table('blockchain').get(hash).run(conn)
        resp['receipt']
      end

      if receipt_hash.present?
        receipt = Tierion::HashApi::Receipt.new(receipt_hash)
      end

      unless receipt.present? && receipt.valid?
        raise "Stored receipt for hash '#{hash}' is invalid"
      end

      confirmations = receipt.confirmations

      next unless confirmations.present? && confirmations['BTCOpReturn']

      # Store the confirmation alongside the hash item receipt
      # with the confirmation timestamp as the value
      $r.connect($rdb_config) do |conn|
        $r.table('blockchain').get(hash).update(
          confirmed: Time.now.utc.iso8601
        ).run(conn)
      end

      # Remove this ID from the confirmation queue
      # Processing chain is complete
      $redis.srem('blockchain:receipt_confirmations_pending_queue', hash)
    end
  end
end
