class BlockchainSendHashWorker
  include Sidekiq::Worker

  # Send a SHA256 hash to Tierion for storage on the blockchain and
  # store it locally in a a database under that hash key. That hash
  # key can then be used later to lookup proof material that proves
  # that that specific key was in fact submitted to the blockchain
  # at a certain time. If you can prove you have materials which,
  # when hashed with SHA256, result in that same hash value that can
  # be used as proof that those values (e.g. crypto keys or the hash
  # of a secret) existed at that time and have remained unchanged.
  def perform(hash)
    unless ENV['TIERION_ENABLED'] == 'true'
      logger.info('Exiting. TIERION_ENABLED is not true. No-Op')
      return nil
    end

    # Send SHA256(hash) to Tierion. The submitted hash value is
    # hashed again before sending to the blockchain so that there
    # is no way to reverse the blockchain value into knowledge
    # of this system.
    blockchain_hash_id = Digest::SHA256.hexdigest(hash)
    hash_item = $blockchain.send(blockchain_hash_id)

    raise 'HashItem was blank' if hash_item.blank?

    # A Redis SET containing all outstanding receipts that still need to be
    # picked up from the API and stored locally. HashItems are processed into
    # receipts every ten minutes. Store the attributes needed to later retrieve
    # the Receipt as a ':' separated string so they can be split apart when
    # receiving receipts in the BlockchainGetReceiptsWorker job. The key used
    # for this queue must match the key in BlockchainGetReceiptsWorker or the
    # ID's of Receipts that need to be retrieved won't be found.
    $redis.sadd('blockchain:receipts_pending_queue', "#{hash}:#{hash_item.id}")

    # Store the HashItem from Tierion.
    $r.connect($rdb_config) do |conn|
      $r.table('blockchain').insert(
        id: hash,
        hash_item: {
          id: hash_item.id,
          timestamp: hash_item.timestamp,
          hash: hash_item.hash
        }
      ).run(conn)
    end
  end
end
