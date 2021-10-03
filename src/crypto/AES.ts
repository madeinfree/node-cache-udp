import crypto, { createDecipheriv } from 'crypto'

import type { HandShakeInfo } from '../types'

import { hash256 } from './hash'

export function encryptPlainText(secretKey: string, msg: string) {
  const iv = crypto.randomBytes(16)

  const hashKey = hash256(secretKey).slice(0, 32)
  const cipher = crypto.createCipheriv('aes-256-gcm', hashKey, iv)
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
  const hashKey = hash256(sInfo.secret).slice(0, 32)
  const decipher = createDecipheriv('aes-256-gcm', hashKey, iv)
  decipher.setAuthTag(tag)
  let decrypted = decipher.update(data, 'hex', 'utf-8')
  decrypted += decipher.final('utf-8')
  return decrypted
}
