import crypto from 'crypto'

export function MACHash256(salt: Buffer, data: string): string {
  return crypto.createHmac('sha256', salt).update(data).digest('hex')
}
