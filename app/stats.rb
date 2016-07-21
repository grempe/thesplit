# Redistat : Store basic system stats
# See : https://github.com/grempe/redistat
class Stats
  include Redistat::Model

  depth :sec
  expire sec: 60.minutes.to_i,
         min: 24.hours.to_i,
         hour: 3.months.to_i,
         day: 10.years.to_i
end
