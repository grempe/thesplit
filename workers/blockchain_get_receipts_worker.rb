class BlockchainGetReceiptsWorker
  include Sidekiq::Worker

  # Retrieve and store all ready Blockchain Receipts
  def perform
    unless ENV.fetch('TIERION_ENABLED') == 'true'
      logger.info('Exiting. TIERION_ENABLED is not true. No-Op')
      return nil
    end

    $redis.smembers('blockchain:receipts_pending_queue').each do |rid|
      server_hash_id, hash_item_id = rid.split(':')

      # Retrieve the receipt from Tierion. The target hash is passed in as well
      # so the Tierion gem client can perform validation on the receipt.
      blockchain_hash_id = Digest::SHA256.hexdigest(server_hash_id)
      r = $blockchain.receipt_from_id_and_hash(hash_item_id, blockchain_hash_id)

      # Receipt not found yet.
      next unless r.present?

      raise "Receipt for ID #{hash_item_id} invalid Merkle tree" unless r.valid?

      # Store the receipt under the server hash ID
      $redis.hset("blockchain:id:#{server_hash_id}", 'receipt', r.to_json)

      # Remove this processed item from the queue
      $redis.srem('blockchain:receipts_pending_queue', rid)

      # queue the retrieval of the receipt confirmation.
      $redis.sadd('blockchain:receipt_confirmations_pending_queue', server_hash_id)
    end
  end
end
