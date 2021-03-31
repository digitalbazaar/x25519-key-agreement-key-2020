/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import nacl from 'tweetnacl';

/**
 * Note: The following two functions are async to match the signature of
 * their native Node.js counterparts (see './crypto.js').
 */

export async function deriveSecret({privateKey, remotePublicKey}) {
  return nacl.scalarMult(privateKey, remotePublicKey);
}

export async function generateKeyPair() {
  // Each is a Uint8Array with 32-byte key
  const {publicKey, secretKey: privateKey} = nacl.box.keyPair();
  return {publicKey, privateKey};
}
