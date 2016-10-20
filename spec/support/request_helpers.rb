module Requests
  module JsonHelpers
    def json_last_response
      JSON.parse(last_response.body)
    end
  end
end
