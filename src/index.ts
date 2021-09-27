import dgram, { RemoteInfo, Socket } from 'dgram'
import EventEmitter from 'events'
import { createDiffieHellman, DiffieHellman, createDecipheriv } from 'crypto'

/**
 * Constants
 */

// PING
const PONG = `4\r\nPONG`
// status
const OK = `OK\r\n`
const ERR = `ERR\r\n`
// number
const ZERO = `0\r\n`

class NodeCacheUDP extends EventEmitter {
  server: Socket | null
  cache: {
    [key: string]: {
      value: string
      length: number
    }
  }
  dh: DiffieHellman
  secret: Buffer
  constructor() {
    super()

    this.server = null
    this.cache = {}

    this.dh = null
    this.secret = null

    this.on('response', this.handleServerResponse)
  }
  public createServer(callback: (address: string, port: number) => void) {
    if (this.server instanceof Socket) {
      console.warn('server has only one instance.')
    } else {
      const server = dgram.createSocket('udp4')
      server.on('error', this.handleServerError)
      server.on('listening', () => {
        const address = server.address()
        if (callback) {
          callback(address.address, address.port)
        } else {
          console.log('server listening %s:%s', address.address, address.port)
        }
      })
      server.on('message', (buffer, remoteInfo) => {
        const text = buffer.toString('utf-8')
        let [op, key, value] = text.split('\r\n')

        if (op !== 'HandShake') {
          const [encrypted, iv, tag] = String(buffer).split(' ')
          const decipher = createDecipheriv(
            'aes-192-gcm',
            this.secret,
            Buffer.from(iv, 'base64')
          )
          decipher.setAuthTag(Buffer.from(tag, 'base64'))
          let decrypted = decipher.update(encrypted, 'hex', 'utf-8')
          decrypted += decipher.final('utf-8')
          const s = decrypted.split('\r\n')
          op = s[0]
          key = s[1]
          value = s[2]
        }

        let responseText = ''
        switch (op) {
          case 'HandShake':
            if (key !== 'phase') {
              const errorMsg = `HandShake \`${key}\` invalid, do you mean \`phase\` ?.`
              responseText = ERR + errorMsg.length + '\r\n' + errorMsg
              break
            }
            const phase = parseInt(value, 10)
            if (phase === 1) {
              const dh = this.handleHandShakeInit()
              const res =
                dh.DHprime.toString('base64') +
                ' ' +
                dh.DHgenerator.toString('base64') +
                ' ' +
                dh.DHKey.toString('base64')
              responseText = OK + res.length + '\r\n' + res
              break
            }
            if (phase === 2) {
              const [, cKey] = value.split(' ')
              this.secret = this.dh.computeSecret(Buffer.from(cKey, 'base64'))
              const res = 'HandShake Success'
              responseText = OK + res.length + '\r\n' + res
            }
            break
          case 'SET':
            this.cache[key] = {
              value,
              length: value.length,
            }
            responseText = OK + ZERO + 'NULL'
            break
          case 'DEL':
            delete this.cache[key]
            responseText = OK + ZERO + 'NULL'
            break
          case 'GET':
            responseText =
              OK +
              (this.cache[key]
                ? `${this.cache[key].length}\r\n${this.cache[key].value}`
                : ZERO + 'NULL')
            break
          case 'PING':
            responseText = OK + PONG
            break
          default:
            responseText =
              ERR + (21 + op.length) + '\r\n' + `\`${op}\` command not found.`
            break
        }

        this.emit('response', remoteInfo, responseText)
      })
      this.server = server
    }
  }
  public bind(port: number = 10923) {
    if (this.server) {
      this.server.bind(port || 10923)
    } else {
      throw Error('Node Cache UDP Error: udp server does not create instance.')
    }
  }
  private handleHandShakeInit() {
    this.dh = createDiffieHellman(192)
    const key = this.dh.generateKeys()
    return {
      DHprime: this.dh.getPrime(),
      DHgenerator: this.dh.getGenerator(),
      DHKey: key,
    }
  }
  private handleServerResponse(remoteInfo: RemoteInfo, msg: string) {
    const { family } = remoteInfo
    if (family === 'IPv4') {
      const { port, address } = remoteInfo
      const client = dgram.createSocket('udp4')
      client.send(Buffer.from(msg), port, address)
    }
  }
  private handleServerError(err: Error) {
    console.log('server error: \n%s', err.stack)
  }
}

export default NodeCacheUDP
