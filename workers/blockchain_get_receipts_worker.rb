class BlockchainGetReceiptsWorker
  include Sidekiq::Worker

  # Retrieve and store all ready for use Blockchain Receipts
  def perform
    unless ENV['TIERION_ENABLED'] == 'true'
      logger.info('Exiting. TIERION_ENABLED is not true. No-Op')
      return nil
    end

    $redis.smembers('blockchain:receipts_pending_queue').each do |rid|
      hash, hash_item_id = rid.split(':')

      # Retrieve the receipt from Tierion. The target hash is passed in as well
      # so the Tierion client can perform validation on the receipt.
      blockchain_hash_id = Digest::SHA256.hexdigest(hash)
      r = $blockchain.receipt_from_id_and_hash(hash_item_id, blockchain_hash_id)

      # Receipt not found yet.
      next unless r.present?

      raise "Receipt for ID #{hash_item_id} has an invalid Merkle tree" unless r.valid?

      # Store the receipt
      $r.connect($rdb_config) do |conn|
        $r.table('blockchain').get(hash).update(
          receipt: r
        ).run(conn)
      end

      # Remove this processed item from the queue
      $redis.srem('blockchain:receipts_pending_queue', rid)

      # Queue the retrieval of the receipt confirmation
      $redis.sadd('blockchain:receipt_confirmations_pending_queue', hash)
    end
  end
end
