class BlockchainSendHashWorker
  include Sidekiq::Worker

  # Send the SHA256 hash to Tierion for storage on the blockchain and
  # store it locally in a Redis hash under the key ID that is the same
  # ID that the secret is stored under.
  def perform(server_hash_id, obj_hash)
    unless ENV['TIERION_ENABLED']
      logger.info('Exiting. TIERION_ENABLED is false or not set. No-Op')
      return nil
    end

    # Send the hash to Tierion
    hash_item = $blockchain.send(obj_hash)

    raise 'HashItem was blank' if hash_item.blank?

    # A Redis SET containing all outstanding receipts that still need to be
    # picked up from the API and stored locally. HashItems are processed into
    # receipts every ten minutes. Store attributes needed to later retrieve
    # the Receipt as a ':' separated string so we can split them apart when
    # receiving receipts in the BlockchainGetReceiptsWorker job.  This key used
    # for this queue must match the key in BlockchainGetReceiptsWorker or the
    # ID's of Receipts that need to be retrieved won't be found.
    $redis.sadd('blockchain:receipts_pending_queue', "#{obj_hash}:#{server_hash_id}:#{hash_item.id}")

    # Store a copy of the HashItem in a Redis hash. Later we'll store the
    # Receipt there also under a new hash key.
    $redis.hset("blockchain:id:#{server_hash_id}", 'hash_item', hash_item.to_json)
  end
end
