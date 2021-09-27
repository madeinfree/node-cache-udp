const dgram = require('dgram')
const crypto = require('crypto')

function base64ToBuffer(code) {
  return Buffer.from(code, 'base64')
}

function encryptPlainText(secretKey, op, key, value) {
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv('aes-192-gcm', secretKey, iv)
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
  constructor(port = 10923, address = 'localhost') {
    this.client = null
    this.address = address
    this.port = port

    this.dhPhase = 0
    this.cKey = null
    this.sKey = null
    this.secretKey = null

    this.createClient()
  }
  createClient() {
    if (this.client instanceof dgram.Socket) {
    } else {
      const client = dgram.createSocket('udp4')
      client.on('message', (buffer) => {
        const [status, length, msg] = buffer.toString().split('\r\n')
        switch (this.dhPhase) {
          case 0:
            const [prime, generator, sKey] = msg.split(' ')
            const dh = crypto.createDiffieHellman(
              base64ToBuffer(prime),
              base64ToBuffer(generator),
              base64ToBuffer(sKey)
            )
            this.sKey = sKey
            this.cKey = dh.generateKeys()
            this.secretKey = dh.computeSecret(base64ToBuffer(sKey))

            this.handShakeLast()

            this.dhPhase++
            break
          case 1:
            this.dhPhase++
            break
          default:
            break
        }
        if (status === 'OK' && this.dhPhase === 2) {
          console.log('length =>', length, 'msg =>', msg)
        }
      })
      client.on('listening', () => {
        const address = client.address()
        console.log(`client listening ${address.address}:${address.port}`)
      })

      client.bind()

      this.client = client

      this.handShakeInit()
    }
  }
  handShakeInit() {
    this.sendRequest(`HandShake\r\nphase\r\n1`)
  }
  handShakeLast() {
    this.sendRequest(`HandShake\r\nphase\r\n2 ${this.cKey.toString('base64')}`)
  }
  get(key) {
    const { encrypted, iv, tag } = encryptPlainText(
      this.secretKey,
      'GET\r\n',
      key,
      ''
    )
    this.sendRequest(
      encrypted + ' ' + iv.toString('base64') + ' ' + tag.toString('base64')
    )
  }
  set(key, value) {
    const { encrypted, iv, tag } = encryptPlainText(
      this.secretKey,
      'SET\r\n',
      key + '\r\n',
      value
    )
    this.sendRequest(
      encrypted + ' ' + iv.toString('base64') + ' ' + tag.toString('base64')
    )
  }
  del(key) {
    const { encrypted, iv, tag } = encryptPlainText(
      this.secretKey,
      'DEL\r\n',
      key,
      ''
    )
    this.sendRequest(
      encrypted + ' ' + iv.toString('base64') + ' ' + tag.toString('base64')
    )
  }
  ping() {
    const { encrypted, iv, tag } = encryptPlainText(
      this.secretKey,
      'PING',
      '',
      ''
    )
    this.sendRequest(
      encrypted + ' ' + iv.toString('base64') + ' ' + tag.toString('base64')
    )
  }
  sendRequest(opText) {
    this.client.send(opText, this.port, this.address)
  }
  close() {
    this.client.close()
  }
}

const client = new NodeCacheClient()

setTimeout(() => {
  client.ping()
}, 1000)
