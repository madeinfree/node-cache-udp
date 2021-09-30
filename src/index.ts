import dgram from 'dgram'

import crypto, { createDecipheriv, createECDH } from 'crypto'
import EventEmitter from 'events'

import type { ECDH } from 'crypto'
import type { RemoteInfo } from 'dgram'
interface HandShakeInfo {
  secret: string
  dh: ECDH
  phase: number
}
interface LiveInfo {
  socket: dgram.Socket | null
  ttl: number
  lastTS: number
}
interface Connection {
  rInfo: RemoteInfo
  sInfo: HandShakeInfo
  lInfo: LiveInfo
}
interface Connections {
  [key: string]: Connection
}

function encryptPlainText(secretKey: string, msg: string) {
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    secretKey.slice(0, 32),
    iv
  )
  let encrypted = cipher.update(msg, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const tag = cipher.getAuthTag()

  return encrypted + ' ' + iv.toString('base64') + ' ' + tag.toString('base64')
}
function decryptData(
  sInfo: HandShakeInfo,
  iv: string,
  tag: string,
  data: string
) {
  const decipher = createDecipheriv(
    'aes-256-gcm',
    sInfo.secret.slice(0, 32),
    Buffer.from(iv, 'base64')
  )
  decipher.setAuthTag(Buffer.from(tag, 'base64'))
  let decrypted = decipher.update(data, 'hex', 'utf-8')
  decrypted += decipher.final('utf-8')
  return decrypted
}

/**
 * Constants
 */

//
const DELIMITER = '\r\n'
// op
const HANDSHAKE = `HandShake`
const SET = 'SET'
const DEL = 'DEL'
const GET = 'GET'
const PING = 'PING'
const CLOSE = 'CLOSE'
// PING
const PONG = '4' + DELIMITER + 'PONG'
// status
const OK = 'OK' + DELIMITER
const ERR = 'ERR' + DELIMITER
// number
const ZERO = '0' + DELIMITER

// konstant
const kServer = Symbol('kServer')
const kCache = Symbol('kCache')
const kConnections = Symbol('kConnections')

/**
 * record connection from client, ttl is default 72000ms
 * key is IP
 */

class NodeCacheUDP extends EventEmitter {
  [kServer]: dgram.Socket | null;
  [kCache]: {
    [key: string]: {
      value: string
      length: number
    }
  };
  [kConnections]: Connections
  constructor() {
    super()

    this[kServer] = null
    this[kCache] = {}

    this[kConnections] = {}

    this.on('response', this.handleServerResponse)
  }
  public createServer(callback: (address: string, port: number) => void) {
    if (this[kServer] instanceof dgram.Socket) {
      console.warn('server has only one instance.')
    } else {
      const server = dgram.createSocket('udp4')
      server.on('error', this.handleServerError)
      server.on('listening', () => {
        const address = server.address()
        if (callback) {
          callback(address.address, address.port)
        } else {
          console.log(
            '[NCU info] server listening %s:%s',
            address.address,
            address.port
          )
        }
      })
      server.on('message', (buffer, remoteInfo) => {
        let port = remoteInfo.port
        let address = remoteInfo.address
        let connect = this[kConnections][address + ':' + port]

        const text = buffer.toString('utf-8')
        let [op, key, value] = text.split(DELIMITER)

        if (op !== HANDSHAKE && !connect) {
          return
        }

        if (op !== HANDSHAKE && connect) {
          const [encrypted, iv, tag] = String(buffer).split(' ')
          const decrypted = decryptData(connect.sInfo, iv, tag, encrypted)
          const s = decrypted.split(DELIMITER)
          op = s[0]
          key = s[1]
          value = s[2]
        } else {
          // record new connection
          if (!connect) {
            connect = this[kConnections][address + ':' + port] = {
              rInfo: remoteInfo,
              sInfo: {
                secret: null,
                dh: null,
                phase: 1,
              },
              lInfo: {
                socket: null,
                ttl: 72000,
                lastTS: new Date().getTime(),
              },
            }
          }
        }

        let responseText = ''
        switch (op) {
          case HANDSHAKE:
            {
              if (key !== 'phase') {
                const errorMsg = `HandShake \`${key}\` invalid, do you mean \`phase\` ?.`
                responseText = ERR + errorMsg.length + DELIMITER + errorMsg
                break
              }
              const phase = parseInt(value, 10)
              if (phase === 1 && connect.sInfo.phase === 1) {
                const dh = this.handleHandShakeInit(connect)
                const res = dh.DHKey.toString('base64')
                responseText = OK + res.length + DELIMITER + res
                this[kConnections][address + ':' + port].sInfo.phase++
                break
              }

              if (phase === 2 && connect.sInfo.phase === 2) {
                const [, cKey] = value.split(' ')
                connect.sInfo.secret = crypto
                  .createHash('sha256')
                  .update(
                    connect.sInfo.dh.computeSecret(Buffer.from(cKey, 'base64'))
                  )
                  .digest('hex')
                const res = 'HandShake Success'
                responseText = OK + res.length + DELIMITER + res
              }
            }
            break
          case SET: {
            this[kCache][key] = {
              value,
              length: value.length,
            }
            responseText = encryptPlainText(
              connect.sInfo.secret,
              OK + ZERO + 'NULL'
            )

            break
          }
          case DEL: {
            delete this[kCache][key]
            responseText = encryptPlainText(
              connect.sInfo.secret,
              OK + ZERO + 'NULL'
            )

            break
          }
          case GET: {
            responseText = encryptPlainText(
              connect.sInfo.secret,
              OK +
                (this[kCache][key]
                  ? this[kCache][key].length +
                    DELIMITER +
                    this[kCache][key].value
                  : ZERO + 'NULL')
            )

            break
          }
          case PING: {
            responseText = encryptPlainText(connect.sInfo.secret, OK + PONG)

            break
          }
          case CLOSE: {
            delete this[kConnections][address + ':' + port]

            break
          }
          default: {
            responseText = encryptPlainText(
              connect.sInfo.secret,
              ERR +
                (21 + op.length) +
                DELIMITER +
                `\`${op}\` command not found.`
            )

            break
          }
        }

        if (op === CLOSE) return
        this.emit('response', connect.rInfo, responseText)
      })
      this[kServer] = server
    }
  }
  public bind(port: number = 10923) {
    if (this[kServer]) {
      this[kServer].bind(port || 10923, () => {
        this.ttlConnectionsChecker()
        console.log('[NCU info] run ttl connection checker...')
      })
    } else {
      throw Error('Node Cache UDP Error: udp server does not create instance.')
    }
  }
  private handleHandShakeInit(connect: Connection) {
    connect.sInfo.dh = createECDH('secp521r1')
    const key = connect.sInfo.dh.generateKeys()
    return {
      DHKey: key,
    }
  }
  private handleServerResponse(remoteInfo: RemoteInfo, msg: string) {
    const { family } = remoteInfo
    if (family === 'IPv4') {
      const { port, address } = remoteInfo
      const client = this[kConnections][address + ':' + port]
      if (client) {
        if (!client.lInfo.socket) {
          client.lInfo.socket = dgram.createSocket('udp4')
        }
        client.lInfo.socket.send(Buffer.from(msg), port, address)

        client.lInfo.lastTS = new Date().getTime()
      }
    }
  }
  private handleServerError(err: Error) {
    console.log('server error: \n%s', err.stack)
  }
  private ttlConnectionsChecker() {
    setTimeout(() => {
      for (let key in this[kConnections]) {
        const diffTS =
          new Date().getTime() - this[kConnections][key].lInfo.lastTS
        if (diffTS > this[kConnections][key].lInfo.ttl) {
          this[kConnections][key].lInfo.socket.close()
          delete this[kConnections][key]
        }
      }
      this.ttlConnectionsChecker()
    }, 10000)
  }
}

export default NodeCacheUDP
