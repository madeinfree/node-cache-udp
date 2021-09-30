const dgram = require('dgram')
const crypto = require('crypto')

function base64ToBuffer(code) {
  return Buffer.from(code, 'base64')
}

function encryptPlainText(secretKey, op, key, value) {
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    secretKey.slice(0, 32),
    iv
  )
  let encrypted = cipher.update(op + key + value, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const tag = cipher.getAuthTag()

  return {
    encrypted,
    iv,
    tag,
  }
}

class NodeCacheClient {
  constructor(settings) {
    this.client = null
    this.port = 10923

    this.host = settings?.host ?? 'localhost'
    this.timeout = settings?.timeout ?? 10000

    this.dhPhase = 0
    this.cKey = null
    this.sKey = null
    this.secretKey = null
  }
  createClient() {
    if (this.client instanceof dgram.Socket) {
    } else {
      const client = dgram.createSocket('udp4')
      return new Promise((resolve) => {
        client.on('message', this.handleHandShake.bind(this, resolve))

        client.once('listening', this.handleListening)
        client.bind()

        this.client = client

        this.handShakeInit()
        this.handShakeTimeout()

        process.on('SIGINT', () => {
          process.exit(0)
        })
      })
    }
  }
  handShakeTimeout() {
    setTimeout(() => {
      if (this.dhPhase !== 2) {
        console.log('[NCUC timeout] Timeout, close connection.')
        this.client.close()
      }
    }, this.timeout)
  }
  handShakeInit() {
    this.sendRequest(Buffer.from([0x1]))
  }
  handleHandShake(resolve, buffer) {
    let [, , msg] = buffer.toString().split('\r\n')
    if (this.dhPhase <= 1) {
      switch (this.dhPhase) {
        case 0:
          const sKey = msg
          const dh = crypto.createECDH('secp521r1')
          this.sKey = sKey
          this.cKey = dh.generateKeys()
          this.secretKey = crypto
            .createHash('sha256')
            .update(dh.computeSecret(base64ToBuffer(sKey)))
            .digest('hex')

          this.handShakeLast()

          this.dhPhase++
          break
        case 1:
          this.dhPhase++
          this.client.removeListener(
            'message',
            this.handleHandShake.bind(this, resolve)
          )
          return resolve(this)
        default:
          break
      }
    }
  }
  handShakeLast() {
    this.sendRequest(
      Buffer.concat([Buffer.from([0x2]), Buffer.from(this.cKey)])
    )
  }
  handleListening() {
    const cInfo = this.address()
    console.log(`client listening ${cInfo.address}:${cInfo.port}`)
  }
  handleResponse(resolve, buffer) {
    let [status, length, msg] = buffer.toString().split('\r\n')
    if (!length && !msg) {
      const [encrypted, iv, tag] = status.split(' ')
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.secretKey.slice(0, 32),
        Buffer.from(iv, 'base64')
      )
      decipher.setAuthTag(Buffer.from(tag, 'base64'))
      let decrypted = decipher.update(encrypted, 'hex', 'utf-8')
      decrypted += decipher.final('utf-8')
      const s = decrypted.split('\r\n')
      status = s[0]
      length = s[1]
      msg = s[2]
    }
    if (status === 'OK' && this.dhPhase === 2) {
      if (msg === 'PONG') {
        console.log('PONG')
      }
      resolve(msg)
    } else if (status === 'ERR') {
      console.log('[NCUC error] length =>', length, 'msg =>', msg)
    }
  }
  get(key) {
    return new Promise((resolve) => {
      const { encrypted, iv, tag } = encryptPlainText(
        this.secretKey,
        'GET\r\n',
        key,
        ''
      )
      this.sendRequest(
        Buffer.concat([Buffer.from([0x82]), iv, tag, Buffer.from(encrypted)])
      )
      this.client.once('message', this.handleResponse.bind(this, resolve))
    })
  }
  set(key, value) {
    return new Promise((resolve) => {
      const { encrypted, iv, tag } = encryptPlainText(
        this.secretKey,
        'SET\r\n',
        key + '\r\n',
        value
      )
      this.sendRequest(
        Buffer.concat([Buffer.from([0x82]), iv, tag, Buffer.from(encrypted)])
      )
      this.client.once('message', this.handleResponse.bind(this, resolve))
    })
  }
  del(key) {
    return new Promise((resolve) => {
      const { encrypted, iv, tag } = encryptPlainText(
        this.secretKey,
        'DEL\r\n',
        key,
        ''
      )
      this.sendRequest(
        Buffer.concat([Buffer.from([0x82]), iv, tag, Buffer.from(encrypted)])
      )
      this.client.once('message', this.handleResponse.bind(this, resolve))
    })
  }
  ping() {
    return new Promise((resolve) => {
      const { encrypted, iv, tag } = encryptPlainText(
        this.secretKey,
        'PING',
        '',
        ''
      )
      this.sendRequest(
        Buffer.concat([Buffer.from([0x82]), iv, tag, Buffer.from(encrypted)])
      )
      this.client.once('message', this.handleResponse.bind(this, resolve))
    })
  }
  close() {
    const { encrypted, iv, tag } = encryptPlainText(
      this.secretKey,
      'CLOSE',
      '',
      ''
    )
    this.sendRequest(
      Buffer.concat([Buffer.from([0x82]), iv, tag, Buffer.from(encrypted)])
    )
    setTimeout(() => {
      this.client.close()
    }, 1000)
  }
  sendRequest(opText) {
    this.client.send(opText, this.port, this.host)
  }
}

module.exports = NodeCacheClient
