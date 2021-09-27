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
// konstant
const kServer = Symbol('kServer')
const kCache = Symbol('kCache')
const kDH = Symbol('kDH')
const kSecret = Symbol('kSecret')

class NodeCacheUDP extends EventEmitter {
  [kServer]: Socket | null;
  [kCache]: {
    [key: string]: {
      value: string
      length: number
    }
  };
  [kDH]: DiffieHellman;
  [kSecret]: Buffer
  constructor() {
    super()

    this[kServer] = null
    this[kCache] = {}

    this[kDH] = null
    this[kSecret] = null

    this.on('response', this.handleServerResponse)
  }
  public createServer(callback: (address: string, port: number) => void) {
    if (this[kServer] instanceof Socket) {
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
            this[kSecret],
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
              this[kSecret] = this[kDH].computeSecret(
                Buffer.from(cKey, 'base64')
              )
              const res = 'HandShake Success'
              responseText = OK + res.length + '\r\n' + res
            }
            break
          case 'SET':
            this[kCache][key] = {
              value,
              length: value.length,
            }
            responseText = OK + ZERO + 'NULL'
            break
          case 'DEL':
            delete this[kCache][key]
            responseText = OK + ZERO + 'NULL'
            break
          case 'GET':
            responseText =
              OK +
              (this[kCache][key]
                ? `${this[kCache][key].length}\r\n${this[kCache][key].value}`
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
      this[kServer] = server
    }
  }
  public bind(port: number = 10923) {
    if (this[kServer]) {
      this[kServer].bind(port || 10923)
    } else {
      throw Error('Node Cache UDP Error: udp server does not create instance.')
    }
  }
  private handleHandShakeInit() {
    this[kDH] = createDiffieHellman(192)
    const key = this[kDH].generateKeys()
    return {
      DHprime: this[kDH].getPrime(),
      DHgenerator: this[kDH].getGenerator(),
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
