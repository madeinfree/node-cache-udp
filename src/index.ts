import dgram from 'dgram'

import crypto from 'crypto'
import EventEmitter from 'events'

import type { RemoteInfo } from 'dgram'
import type { Connections } from './types'

import { decryptData, encryptPlainText } from './crypto/AES'

/** 
  HandShake Flag 1 byte
  phase = 1 0x1 = 00000001
  handshake uncomplet = 0x00 = 00000000 
  handshake completed = 0x80 = 10000000
  handshake completed = 0x82 = 10000010
  
  aes-256-gcm cipher iv 16 bytes
  aes-256-gcm cipher tag 16 bytes
 */

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
        let op, key, value

        const isHandShaked = (buffer[0] & 0x80) > 0
        if (!isHandShaked) {
          op = HANDSHAKE
        }

        if (isHandShaked && connect) {
          const iv = buffer.slice(1, 17)
          const tag = buffer.slice(17, 33)
          const encrypted = buffer.slice(33).toString()
          const decrypted = decryptData(connect.sInfo, iv, tag, encrypted)
          const s = decrypted.split(DELIMITER)
          op = s[0]
          key = s[1]
          value = s[2]
        }
        if (!isHandShaked && !connect) {
          // record new connection
          connect = this[kConnections][address + ':' + port] = {
            rInfo: remoteInfo,
            sInfo: {
              secret: null,
              dh: null,
              phase: 1,
            },
          }
        }

        let packet: string = ''
        switch (op) {
          case HANDSHAKE:
            {
              const phase = buffer[0] & 0x3
              if (phase === 1 && connect.sInfo.phase === 1) {
                const cHDKey = buffer.slice(1)
                const dh = crypto.createECDH('secp521r1')
                const sHDKey = dh.generateKeys()
                connect.sInfo.secret = crypto
                  .createHash('sha256')
                  .update(dh.computeSecret(cHDKey))
                  .digest('hex')
                packet = OK + sHDKey.length + '\r\n' + sHDKey.toString('base64')
                connect.sInfo.phase++
              }
            }
            break
          case SET: {
            this[kCache][key] = {
              value,
              length: value.length,
            }
            packet = encryptPlainText(connect.sInfo.secret, OK + ZERO + 'NULL')

            break
          }
          case DEL: {
            delete this[kCache][key]
            packet = encryptPlainText(connect.sInfo.secret, OK + ZERO + 'NULL')

            break
          }
          case GET: {
            packet = encryptPlainText(
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
            packet = encryptPlainText(connect.sInfo.secret, OK + PONG)

            break
          }
          case CLOSE: {
            delete this[kConnections][address + ':' + port]

            break
          }
          default: {
            packet = encryptPlainText(
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
        this.emit('response', connect.rInfo, packet)
      })
      this[kServer] = server
    }
  }
  public bind(port: number = 10923) {
    if (this[kServer]) {
      this[kServer].bind(port || 1092)
    } else {
      throw Error('Node Cache UDP Error: udp server does not create instance.')
    }
  }
  private handleServerResponse(remoteInfo: RemoteInfo, msg: string) {
    const { family } = remoteInfo
    if (family === 'IPv4') {
      const { port, address } = remoteInfo
      const client = this[kConnections][address + ':' + port]
      if (client) {
        this[kServer].send(Buffer.from(msg), port, address)
      }
    }
  }
  private handleServerError(err: Error) {
    console.log('server error: \n%s', err.stack)
  }
}

export default NodeCacheUDP
