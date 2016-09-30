class BlockchainSendHashWorker
  include Sidekiq::Worker

  # Send the SHA256 hash to Tierion for storage on the blockchain and
  # store it locally in a Redis hash under the key ID that is the same
  # ID that the secret is stored under.
  def perform(server_hash_id)
    unless ENV.fetch('TIERION_ENABLED') == 'true'
      logger.info('Exiting. TIERION_ENABLED is not true. No-Op')
      return nil
    end

    # Send the hash to Tierion. This is a SHA256 of the server_hash_id
    # so it can also be verified by a recipient without touching this
    # server, with an extra measure of indirection by giving the blockchain
    # something it can't reverse into knowledge of this system.
    blockchain_hash_id = Digest::SHA256.hexdigest(server_hash_id)
    hash_item = $blockchain.send(blockchain_hash_id)

    raise 'HashItem was blank' if hash_item.blank?

    # A Redis SET containing all outstanding receipts that still need to be
    # picked up from the API and stored locally. HashItems are processed into
    # receipts every ten minutes. Store attributes needed to later retrieve
    # the Receipt as a ':' separated string so we can split them apart when
    # receiving receipts in the BlockchainGetReceiptsWorker job.  This key used
    # for this queue must match the key in BlockchainGetReceiptsWorker or the
    # ID's of Receipts that need to be retrieved won't be found.
    $redis.sadd('blockchain:receipts_pending_queue', "#{server_hash_id}:#{hash_item.id}")

    # Store a copy of the HashItem. Later we'll store the
    # Receipt there as well.
    $r.connect($rdb_config) do |conn|
      $r.table('blockchain').insert(
        id: server_hash_id,
        hash_item: {
          id: hash_item.id,
          timestamp: hash_item.timestamp,
          hash: hash_item.hash
        }
      ).run(conn)
    end
  end
end
