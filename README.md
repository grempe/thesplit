# [thesplit.is](https://thesplit.is)

[![Build Status](https://travis-ci.org/thesplit/thesplit.svg?branch=master)](https://travis-ci.org/thesplit/thesplit)

The open-source, end-to-end encrypted, zero-knowledge, auto-expiring, cryptographically secure, secret sharing service.

We all have secrets. Send yours safely.

[https://thesplit.is](https://thesplit.is)

## Run Your Own

Trust issues? Want to run your own copy of this application on Heroku?

Use this [Heroku button](https://blog.heroku.com/heroku-button) to perform
a free one-click install of a new private instance of this application
on Heroku. This will configure a single Heroku Dyno and an instance of
the Redis Cloud Redis DB addon. The source code will be pulled from the master
branch of the [github.com/thesplit/thesplit](https://github.com/thesplit/thesplit)
repository.

You will also need your own instance (or high-availability cluster) of Hashicorp's
Vault running. This encrypted vault is where all security sensitive application
data is stored.

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/thesplit/thesplit)

## Development

This repository contains the Ruby (Sinatra) API server source code for `thesplit`.

The Vue.js based client source code can be found in the [github.com/thesplit/thesplit-vue](https://github.com/thesplit/thesplit-vue)
repository. Here you'll find only a copy of the ready to use Javascript from `thesplit-vue/dist` dir under `public/js/build.*` which will be periodically updated
when releases are cut from there.

Although the primary data store for this application is Redis, no Redis
instance is needed in the `development` or `test` environments since [MockRedis](https://github.com/brigade/mock_redis) is used. Keep in mind that as
a result no data will persist between server restarts unless in `production`.

Setup

```
bundle install
```

Run a local dev server and run specs on file changes.

```
bundle exec guard
```

Open a console

```
bundle exec pry -r./config/environment.rb
```

Run Rspec specs

```
bundle exec rspec
```

Run ONLY Rspec tests with Guard (watching for file changes)

```
bundle exec guard -P rspec
```

Run Rspec tests as Travis-CI would

```
rake wwtd           # test on all combinations defined in .travis.yml
rake wwtd:bundle    # bundle for all combinations
rake wwtd:local     # test on all combinations defined in .travis.yml on current ruby
rake wwtd:parallel  # test on all combinations defined in .travis.yml in parallel
```

## Legal

### Copyright

```txt
Copyright (c) 2016 Glenn Rempe All Rights Reserved.
```

### License

![GNU Affero General Public License](http://www.gnu.org/graphics/agplv3-155x51.png)

```txt

thesplit - An API server to support the secure sharing of secrets.
Copyright (c) 2016  Glenn Rempe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


```

A copy of the [GNU Affero General Public License](http://www.gnu.org/licenses/agpl.html) can be found in the [LICENSE.txt](https://github.com/thesplit/thesplit/blob/master/LICENSE.txt) file.

### Contact

```
Glenn Rempe
email : glenn@rempe.us
twitter : @grempe
```
