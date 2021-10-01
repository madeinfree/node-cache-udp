import type { ECDH } from 'crypto'
import type { Socket, RemoteInfo } from 'dgram'

interface HandShakeInfo {
  secret: string
  dh: ECDH
  phase: number
}
interface Connection {
  rInfo: RemoteInfo
  sInfo: HandShakeInfo
}
interface Connections {
  [key: string]: Connection
}
