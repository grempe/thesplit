class BlockchainGetReceiptsWorker
  include Sidekiq::Worker

  # Retrieve and store all ready Blockchain Receipts
  def perform
    unless ENV['TIERION_ENABLED']
      logger.info('Exiting. TIERION_ENABLED is false or not set. No-Op')
      return nil
    end

    $redis.smembers('blockchain:receipts_pending_queue').each do |rid|
      obj_hash, server_hash_id, hash_item_id = rid.split(':')

      # Retrieve the receipt from Tierion.
      r = $blockchain.receipt_from_id_and_hash(hash_item_id, obj_hash)

      # receipt not found yet.
      next unless r.present?
      raise "Receipt for ID #{hash_item_id} invalid Merkle tree" unless r.valid?

      # store the receipt under the server hash ID
      $redis.hset("blockchain:id:#{server_hash_id}", 'receipt', r.to_json)

      # remove this processed item from the queue
      $redis.srem('blockchain:receipts_pending_queue', rid)

      # queue the retrieval of the receipt confirmation.
      $redis.sadd('blockchain:receipt_confirmations_pending_queue', "#{server_hash_id}")
    end
  end
end
