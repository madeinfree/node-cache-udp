import dgram from 'dgram'

import crypto from 'crypto'
import EventEmitter from 'events'

import type { ECDH } from 'crypto'
import type { RemoteInfo } from 'dgram'
import type { Connections, ConstructorOptions } from './types'

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
 * Packet
 * status 1 byte
 * public key 12 bytes
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
// status
const OK = Buffer.from([0x1])
const ERR = Buffer.from([0x4])
// PING
const PONGB = Buffer.from([0x50, 0x4f, 0x4e, 0x47]) // PONG
const PONG = Buffer.concat([OK, PONGB])
// number
const ZERO = '0' + DELIMITER

// konstant
const kServer = Symbol('kServer')
const kCache = Symbol('kCache')
const kConnections = Symbol('kConnections')
const kConfig = Symbol('kConfig')

/**
 * record connection from client, ttl is default 72000ms
 * key is IP
 */

class NodeCacheUDP extends EventEmitter {
  [kServer]: dgram.Socket | null;
  [kConfig]: {
    ca?: string
    key?: string
    ecdh: ECDH
    lternPublicKey: Buffer
  };
  [kCache]: {
    [key: string]: {
      value: string
      length: number
    }
  };
  [kConnections]: Connections
  constructor(options: ConstructorOptions = {}) {
    super()

    this[kServer] = null
    this[kConfig] = {
      ecdh: null,
      lternPublicKey: null,
    }
    this[kCache] = {}
    this[kConnections] = {}

    this.initServer(options)

    this.on('response', this.handleServerResponse)
  }
  public initServer(options: ConstructorOptions) {
    if (options.ca && options.key) {
      this[kConfig].ca = options.ca
      this[kConfig].key = options.key
      this[kConfig].ecdh = crypto.createECDH('secp521r1')
      this[kConfig].ecdh.generateKeys()
      this[kConfig].lternPublicKey = this[kConfig].ecdh.getPublicKey()
    }
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
        if (!isHandShaked) {
          op = HANDSHAKE
        }

        let packet: string | Buffer = ''
        let noPacket = false
        switch (op) {
          case HANDSHAKE:
            {
              const phase = buffer[0] & 0x3
              if (phase & 1 && connect.sInfo.phase === 1) {
                const sign = crypto.createSign('SHA256')
                sign.update(
                  Buffer.concat([
                    this[kConfig].lternPublicKey,
                    Buffer.from(this[kConfig].ca),
                  ])
                )
                sign.end()
                const signature = sign.sign(this[kConfig].key)
                packet = Buffer.concat([
                  Buffer.from([0x1, 0x85]),
                  this[kConfig].lternPublicKey,
                  signature,
                  Buffer.from(this[kConfig].ca),
                ])
                connect.sInfo.phase++
              }
              if (phase & 2 && connect.sInfo.phase === 2) {
                const cipherText = buffer.slice(2)
                const decrypted = crypto.privateDecrypt(
                  this[kConfig].key,
                  cipherText
                )
                connect.sInfo.secret = crypto
                  .createHash('sha256')
                  .update(this[kConfig].ecdh.computeSecret(decrypted))
                  .digest('hex')
                noPacket = true
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
            packet = encryptPlainText(connect.sInfo.secret, 'OK\r\n4\r\nPONG')

            break
          }
          case CLOSE: {
            delete this[kConnections][address + ':' + port]
            noPacket = true

            break
          }
          default: {
            packet = encryptPlainText(
              connect.sInfo.secret,
              'ERR\r\n' +
                (21 + op.length) +
                DELIMITER +
                `\`${op}\` command not found.`
            )

            break
          }
        }
        if (noPacket) return
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
