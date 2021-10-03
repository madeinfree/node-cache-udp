import crypto from 'crypto'

export function hash256(data: string): string {
  const hash = crypto.createHash('sha256').update(data).digest('hex')
  return hash
}
