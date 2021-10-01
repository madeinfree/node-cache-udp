import crypto, { createDecipheriv } from 'crypto'

import type { HandShakeInfo } from '../types'

export function encryptPlainText(secretKey: string, msg: string) {
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
export function decryptData(
  sInfo: HandShakeInfo,
  iv: Buffer,
  tag: Buffer,
  data: string
) {
  const decipher = createDecipheriv(
    'aes-256-gcm',
    sInfo.secret.slice(0, 32),
    iv
  )
  decipher.setAuthTag(tag)
  let decrypted = decipher.update(data, 'hex', 'utf-8')
  decrypted += decipher.final('utf-8')
  return decrypted
}
