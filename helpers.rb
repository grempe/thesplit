helpers do
  # Integrity check helper. Ensure the content that will be
  # stored, or that has been retrieved, matches exactly
  # what was HMAC'ed on the client using BLAKE2s with
  # a shared pepper and 16 Byte output.
  def valid_hash?(client_hash, server_arr)
    b2_pepper = Blake2::Key.from_string('zerotime')
    server_hash = Blake2.hex(server_arr.join, b2_pepper, 16)
    # secure constant-time string comparison
    if RbNaCl::Util.verify32(server_hash, client_hash)
      return true
    else
      logger.warn "valid_hash? : false : #{client_hash} : #{server_hash}"
      return false
    end
  end

  # Capture basic aggregate statistics
  def stats_increment(metric)
    raise 'invalid metric' unless metric.is_a?(String)
    t = Time.now.utc
    stats_base = 'zerotime:stats'
    total_key = "#{stats_base}:#{metric}"
    total_year_key = "#{total_key}:#{t.year}"
    total_month_key = "#{total_year_key}:#{t.month}"
    total_day_key = "#{total_month_key}:#{t.day}"
    total_hour_key = "#{total_day_key}:#{t.hour}"

    settings.redis.incr(total_key)
    settings.redis.incr(total_year_key)
    settings.redis.incr(total_month_key)
    settings.redis.incr(total_day_key)
    settings.redis.incr(total_hour_key)
  end

  def stat_total(metric)
    num = settings.redis.get("zerotime:stats:#{metric}")
    num.nil? ? 0 : num
  end

  def stat_year(metric)
    t = Time.now.utc
    num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}")
    num.nil? ? 0 : num
  end

  def stat_month(metric)
    t = Time.now.utc
    num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}")
    num.nil? ? 0 : num
  end

  def stat_day(metric)
    t = Time.now.utc
    num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}:#{t.day}")
    num.nil? ? 0 : num
  end

  def stat_hour(metric)
    t = Time.now.utc
    num = settings.redis.get("zerotime:stats:#{metric}:#{t.year}:#{t.month}:#{t.day}:#{t.hour}")
    num.nil? ? 0 : num
  end
end
