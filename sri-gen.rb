#!/usr/bin/env ruby

###############################################################################
#
# thesplit - An API server to support the secure sharing of secrets.
# Copyright (c) 2016  Glenn Rempe
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

# ABOUT
# A simple tool to generate Sub Resource Integrity hashes
# and store them in a JSON file which can also be versioned
# or consumed programatically.

require 'digest/sha2'
require 'json'

files = {}

Dir.glob('public/**/*.{js,css}').each do |file_name|
  next if File.directory? file_name
  files[file_name] = "sha384-#{Digest::SHA384.file(file_name).base64digest}"
end

File.open('sri-hashes.json','w') do |f|
  f.write(JSON.pretty_generate(files))
end
