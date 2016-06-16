// See : https://github.com/joaquimserafim/base64-url
function base64unescape(str) {
  return (str + Array(5 - str.length % 4)
    .join('='))
    .replace(/\-/g, '+')
    .replace(/_/g, '/')
}

function base64escape(str) {
  return str.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

const baseUrl = location.protocol + '//' + location.host

// Send POST requests a form encoded instead of JSON bodies
// Sinatra uses the former by default.
Vue.http.options.emulateJSON = true

var secret = new Vue({
  el: '#inputSecretGroup',
  data: {
    secret: '',
    secretNonce: null,
    secretKey: null,
    secretBox: null,
    pendingSubmit: true,
    uuid: null,
    createdAt: null,
    expiresAt: null
  },
  computed: {
    secretBytes: function () {
      if (this.secret) {
        return nacl.util.decodeUTF8(this.secret)
      }
    },
    secretNonceBytes: function () {
      if (this.secretNonce) {
        return this.secretNonce
      } else {
        this.secretNonce = nacl.randomBytes(24)
        return this.secretNonce
      }
    },
    secretKeyBytes: function () {
      if (this.secretKey) {
        return this.secretKey
      } else {
        this.secretKey = nacl.randomBytes(32)
        return this.secretKey
      }
    },
    secretBoxBytes: function () {
      if (this.secretBox) {
        return this.secretBox
      } else {
        sb = nacl.secretbox(this.secretBytes, this.secretNonceBytes, this.secretKeyBytes)
        this.secretBox = sb
        return sb
      }
    },
    secretBytesB64: function () {
      if (this.secretBytes) {
        return base64escape(nacl.util.encodeBase64(this.secretBytes))
      }
    },
    secretNonceBytesB64: function () {
      if (this.secretNonceBytes) {
        return base64escape(nacl.util.encodeBase64(this.secretNonceBytes))
      }
    },
    secretKeyBytesB64: function () {
      if (this.secretKeyBytes) {
        return base64escape(nacl.util.encodeBase64(this.secretKeyBytes))
      }
    },
    secretBoxBytesB64: function () {
      if (this.secretBoxBytes) {
        return base64escape(nacl.util.encodeBase64(this.secretBoxBytes))
      }
    },
    secretUrl: function () {
      if (this.uuid && this.secretKeyBytesB64) {
        return baseUrl + '/' + this.uuid + '?k=' + this.secretKeyBytesB64
      }
    }
  },
  methods: {
    resetAll: function () {
      this.secret = null
      this.resetSecretData()
      this.resetResponseData()
      this.resetUI()
    },
    resetOnInputKeyup: function () {
      this.resetSecretData()
      this.resetResponseData()
      this.resetUI()
    },
    resetSecretData: function () {
      this.secretNonce = null
      this.secretKey = null
      this.secretBox = null
    },
    resetResponseData: function () {
      this.uuid = null
      this.createdAt = null
      this.expiresAt = null
    },
    resetUI: function () {
      this.pendingSubmit = true
    },
    submitSecret: function (event) {
      // Use BLAKE2s in HMAC keyed mode with a pepper.
      var hashKey = nacl.util.decodeUTF8('zerotime')
      var h = new BLAKE2s(32, hashKey)
      h.update(nacl.util.decodeUTF8(this.secretNonceBytesB64))
      h.update(nacl.util.decodeUTF8(this.secretBoxBytesB64))

      var data = {}
      data.secretNonceBytesB64 = this.secretNonceBytesB64
      data.secretBoxBytesB64 = this.secretBoxBytesB64
      data.blake2sHash = h.hexDigest()

      this.pendingSubmit = false

      this.$http.post(baseUrl + '/secret', {
          'data': JSON.stringify(data)
        }, function (data) {
          this.secret = null
          this.resetSecretData()
          this.$set('uuid', data.uuid)
          this.$set('createdAt', data.created_at)
          this.$set('expiresAt', data.expires_at)
        })
        .catch(function (data, status, request) {
          // handle error
          this.resetUI()
        })
    }
  }
})
