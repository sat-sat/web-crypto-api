const crypto = require('crypto')
const { webcrypto } = crypto
const { subtle } = webcrypto

interface KeyObject {
  type: string
  extractable: boolean
  algorithm: {
    name: string
    modulusLength: number
    publicExponent: Uint8Array[]
    hash: Record<string, unknown>
  }
  usages: string[]
}

let privateKeyObject: KeyObject
let publicKeyObject: KeyObject
let signature: ArrayBuffer
const rawData = 'Raw Data'

const convertStringToArrayBufferView = (val: string) => {
  let bytes = new Uint8Array(val.length)
  for (let i = 0; i < val.length; i++) {
    bytes[i] = val.charCodeAt(i)
  }

  return bytes
}

/**
 * Params:
 * 1. Asymmetric Encryptioni algorith name and its requirements
 * 2. Boolean indicating it is extractable, which indicates whether or not the raw keying material may be exported by the application
 * 3. Usage of the keys
 */
const promiseKey = async () => {
  return await subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-256' }
    },
    false,
    ['sign', 'verify']
  )
}

const setKeys = async () => {
  const { privateKey, publicKey } = await promiseKey()
  privateKeyObject = privateKey
  publicKeyObject = publicKey
}

const encryptData = async () => {
  try {
    const response = await subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKeyObject,
      convertStringToArrayBufferView(rawData)
    )
    signature = response
    console.log('encryption result: ', signature)
  } catch (e) {
    console.log('error while encrypting: ', e)
  }
}

const decryptData = async () => {
  try {
    const response = await subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      publicKeyObject,
      signature,
      convertStringToArrayBufferView(rawData)
    )
    console.log('decryption result: ', response)
  } catch (e) {
    console.log('error while decrypting: ', e)
  }
}

const main = async () => {
  await setKeys()
  await encryptData()
  await decryptData()
}

main()
