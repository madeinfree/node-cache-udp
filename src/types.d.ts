import type { ECDH } from 'crypto'
import type { Socket, RemoteInfo } from 'dgram'

export interface HandShakeInfo {
  secret: string
  dh: ECDH
  phase: number
}
export interface LiveInfo {
  socket: Socket | null
  ttl: number
  lastTS: number
}
export interface Connection {
  rInfo: RemoteInfo
  sInfo: HandShakeInfo
  lInfo: LiveInfo
}
interface Connections {
  [key: string]: Connection
}
