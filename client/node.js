const dgram = require('dgram')
const crypto = require('crypto')
const forge = require('node-forge')

const pki = forge.pki
const MACSalt = Buffer.alloc(32).fill(0x0)

function verifiyFromCACerts(certsContext, verifyCert) {
  const verifyX509 = new crypto.X509Certificate(verifyCert)
  for (let i = 0; i < certsContext.length; i++) {
    const certX509 = new crypto.X509Certificate(certsContext[i])
    if (verifyX509.checkIssued(certX509)) {
      return true
    }
  }
  return false
}

function hmac_sha256(salt, data) {
  return crypto.createHmac('sha256', salt).update(data).digest('hex')
}

function encryptPlainText(secret, value) {
  const iv = crypto.randomBytes(16)

  const hashKey = hmac_sha256(MACSalt, secret).slice(0, 32)
  const cipher = crypto.createCipheriv('aes-256-gcm', hashKey, iv)
  let encrypted = cipher.update(value, 'utf-8', 'hex')
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

    this.host = settings.host || 'localhost'
    this.timeout = settings.timeout || 10000
    this.certsContext = settings.certs ? [...settings.certs] : []

    this.dhPhase = 1
    this.publicKey = null
    this.secret = null
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
    this.sendRequest(Buffer.concat([Buffer.from([0x1])]))
  }
  handleHandShake(resolve, buffer) {
    if (this.dhPhase <= 1) {
      switch (this.dhPhase) {
        case 1:
          const status = buffer[0] & 0x1
          const len = buffer[1] & 0xff
          if (status && len) {
            const sPublicKey = buffer.slice(2, 135)
            const signature = buffer.slice(135, 391)
            const cert = pki.certificateFromPem(buffer.slice(391).toString())
            const publicKey = pki.publicKeyToPem(cert.publicKey)

            const verify = crypto.createVerify('SHA256')
            verify.update(Buffer.concat([sPublicKey, buffer.slice(391)]))
            verify.end()
            const isVerify = verify.verify(publicKey, signature)
            const isVerifyCACert = verifiyFromCACerts(
              this.certsContext,
              buffer.slice(391).toString()
            )
            if (!isVerify || !isVerifyCACert) {
              console.warn(
                '[NCUC certerror]: server certificate signature invalidate'
              )
              return
            }

            const dh = crypto.createECDH('secp521r1')
            dh.generateKeys()
            this.publicKey = dh.getPublicKey()
            this.secret = crypto
              .createHash('sha256')
              .update(dh.computeSecret(sPublicKey))
              .digest('hex')

            const encrypted = crypto.publicEncrypt(publicKey, this.publicKey)
            const packet = Buffer.concat([
              Buffer.from([0x02]),
              Buffer.from([0x0]),
              Buffer.from(encrypted),
            ])

            this.sendRequest(packet)
            this.dhPhase++
            return resolve(this)
          }
          throw new Error('server handshake error')
        default:
          break
      }
    }
  }
  handleListening() {
    const cInfo = this.address()
    console.log(`client listening ${cInfo.address}:${cInfo.port}`)
  }
  handleResponse(resolve, buffer) {
    let [status, length, msg] = buffer.toString().split('\r\n')
    if (!length && !msg) {
      const [encrypted, iv, tag] = status.split(' ')
      const hashKey = hmac_sha256(MACSalt, this.secret).slice(0, 32)
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        hashKey,
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
        this.secret,
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
        this.secret,
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
        this.secret,
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
        this.secret,
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
      this.secret,
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
