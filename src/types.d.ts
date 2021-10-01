import type { ECDH } from 'crypto'
import type { Socket, RemoteInfo } from 'dgram'

interface HandShakeInfo {
  secret: string
  dh: ECDH
  phase: number
}
interface LiveInfo {
  socket: Socket | null
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
