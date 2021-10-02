import type { ECDH } from 'crypto'
import type { RemoteInfo } from 'dgram'

interface ConstructorOptions {
  ca?: string
  key?: string
}
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
