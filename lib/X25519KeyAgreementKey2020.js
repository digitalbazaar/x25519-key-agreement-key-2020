/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {LDKeyPair} from 'crypto-ld';
import ed2curve from 'ed2curve';
import * as base58btc from 'base58-universal';

import {generateKeyPair, deriveSecret} from './crypto.js';

const SUITE_ID = 'X25519KeyAgreementKey2020';

/**
 * Encodes a given Uint8Array to multibase-encoded string.
 *
 * @param {Uint8Array} bytes - Bytes to encode.
 * @returns {string} Multibase-encoded string.
 */
function _multibaseEncode({bytes}) {
  // prefix with `z` to indicate multi-base base58btc encoding
  return `z${base58btc.encode(bytes)}`;
}

/**
 * Decodes a given multibase-encoded string.
 *
 * @param {string} text - Multibase encoded string to decode.
 * @returns {Uint8Array} Decoded bytes.
 */
function _multibaseDecode({text}) {
  // drop the initial multibase 'z' prefix
  return base58btc.decode(text.substr(1));
}

export class X25519KeyAgreementKey2020 extends LDKeyPair {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.controller - Controller DID or document url.
   * @param {string} [options.id] - Key id, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} options.publicKeyMultibase - Multibase encoded Public Key.
   * @param {string} [options.privateKeyMultibase] - Multibase Private Key.
   */
  constructor(options = {}) {
    super(options);
    this.type = SUITE_ID;
    this.publicKeyMultibase = options.publicKeyMultibase;
    if(!this.publicKeyMultibase) {
      throw TypeError('The "publicKeyMultibase" property is required.');
    }
    this.privateKeyMultibase = options.privateKeyMultibase;
    if(this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }
  }

  /**
   * Generates a new public/private X25519 Key Pair.
   *
   * @param {object} [options={}] - Keypair options (see controller docstring).
   *
   * @returns {Promise<X25519KeyAgreementKey2020>} Generated key pair.
   */
  static async generate(options = {}) {
    const {publicKey, privateKey} = await generateKeyPair();

    return new X25519KeyAgreementKey2020({
      publicKeyMultibase: _multibaseEncode({bytes: publicKey}),
      privateKeyMultibase: _multibaseEncode({bytes: privateKey}),
      ...options
    });
  }

  /**
   * Creates an X25519KeyAgreementKey2020 Key Pair from an existing key
   * (constructor method).
   *
   * @param {object} [options={}] - Keypair options (see controller docstring).
   *
   * @returns {X25519KeyAgreementKey2020} An X25519 Key Pair.
   */
  static async from(options = {}) {
    return new X25519KeyAgreementKey2020(options);
  }

  /**
   * Converts a keypair instance of type Ed25519VerificationKey2020 to an
   * instance of this class.
   *
   * @see https://github.com/digitalbazaar/ed25519-verification-key-2020
   *
   * @param {object} [options={}] - Options hashmap.
   *
   * @typedef {object} Ed25519VerificationKey2020
   * @param {Ed25519VerificationKey2020} options.keyPair - Source key pair.
   *
   * @returns {X25519KeyAgreementKey2020} A derived/converted key agreement
   *   key pair.
   */
  static fromEd25519VerificationKey2020({keyPair} = {}) {
    if(!keyPair.publicKeyMultibase) {
      throw new Error('Source public key is required to convert.');
    }

    if(!keyPair.publicKeyMultibase.startsWith('z')) {
      throw new TypeError(
        'Expecting source public Ed25519 2020 key to have base58btc encoding.'
      );
    }

    const xKey = new X25519KeyAgreementKey2020({
      controller: keyPair.controller,
      publicKeyMultibase: X25519KeyAgreementKey2020
        .convertFromEdPublicKey(keyPair)
    });

    if(keyPair.privateKeyMultibase) {
      if(!keyPair.privateKeyMultibase.startsWith('z')) {
        throw new TypeError(
          // eslint-disable-next-line max-len
          'Expecting source private Ed25519 2020 key to have base58btc encoding.'
        );
      }

      xKey.privateKeyMultibase = X25519KeyAgreementKey2020
        .convertFromEdPrivateKey(keyPair);
    }

    return xKey;
  }

  /**
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyMultibase - Multibase encoded Ed25519
   *   public key.
   *
   * @returns {string} Multibase encoded converted X25519 Public key.
   */
  static convertFromEdPublicKey({publicKeyMultibase} = {}) {
    if(!publicKeyMultibase) {
      throw new Error('Source public key is required to convert.');
    }

    const edPubkeyBytes = _multibaseDecode({text: publicKeyMultibase});

    // Converts a 32-byte Ed25519 public key into a 32-byte Curve25519 key
    // Returns null if the given public key in not a valid Ed25519 public key.
    const dhPubkeyBytes = ed2curve.convertPublicKey(edPubkeyBytes);
    if(!dhPubkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 public key.');
    }
    return _multibaseEncode({bytes: dhPubkeyBytes});
  }

  /**
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.privateKeyMultibase - Multibase encoded Ed25519
   *   private key.
   *
   * @returns {string} Multibase encoded converted X25519 Private key.
   */
  static convertFromEdPrivateKey({privateKeyMultibase} = {}) {
    if(!privateKeyMultibase) {
      throw new Error('Source private key is required to convert.');
    }

    const edPrivkeyBytes = _multibaseDecode({text: privateKeyMultibase});
    // Converts a 64-byte Ed25519 secret key (or just the first 32-byte part of
    // it, which is the secret value) into a 32-byte Curve25519 secret key
    const dhPrivkeyBytes = ed2curve.convertSecretKey(edPrivkeyBytes);
    if(!dhPrivkeyBytes) {
      throw new Error(
        'Error converting to X25519; Invalid Ed25519 private key.');
    }
    return _multibaseEncode({bytes: dhPrivkeyBytes});
  }

  /**
   * Exports the serialized representation of the KeyPair.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {boolean} [options.publicKey] - Export public key material?
   * @param {boolean} [options.privateKey] - Export private key material?
   *
   * @returns {object} A plain js object that's ready for serialization
   *   (to JSON, etc), for use in DIDs etc.
   */
  export({publicKey = false, privateKey = false} = {}) {
    if(!(publicKey || privateKey)) {
      throw new TypeError(
        'Export requires specifying either "publicKey" or "privateKey".');
    }
    const exportedKey = {
      id: this.id,
      type: this.type,
      controller: this.controller
    };
    if(publicKey) {
      exportedKey.publicKeyMultibase = this.publicKeyMultibase;
    }
    if(privateKey) {
      exportedKey.privateKeyMultibase = this.privateKeyMultibase;
    }
    return exportedKey;
  }

  /**
   * Generates and returns a multiformats encoded
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyMultibase - Multibase encoded public key.
   *
   * @returns {string} The fingerprint.
   */
  static fingerprintFromPublicKey({publicKeyMultibase} = {}) {
    if(!publicKeyMultibase) {
      throw new Error('Source public key is required.');
    }
    // X25519 cryptonyms are multicodec encoded values, specifically:
    // (multicodec('x25519-pub') + key bytes)
    const pubkeyBytes = _multibaseDecode({text: publicKeyMultibase});
    const buffer = new Uint8Array(2 + pubkeyBytes.length);
    // See https://github.com/multiformats/multicodec/blob/master/table.csv
    // 0xec is the value for X25519 public key
    // 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
    // See https://github.com/multiformats/unsigned-varint
    buffer[0] = 0xec; //
    buffer[1] = 0x01;
    buffer.set(pubkeyBytes, 2);
    return _multibaseEncode({bytes: buffer});
  }

  /**
   * Creates an instance of X25519KeyAgreementKey2020 from a key fingerprint.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.fingerprint - Public key fingerprint.
   *
   * @returns {X25519KeyAgreementKey2020} Key pair instance (public key material
   *   only) created from the fingerprint.
   */
  static fromFingerprint({fingerprint} = {}) {
    if(!fingerprint ||
      !(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      throw new Error('`fingerprint` must be a multibase encoded string.');
    }
    const buffer = _multibaseDecode({text: fingerprint});

    // buffer is: 0xec 0x01 <public key bytes>
    if(buffer[0] !== 0xec || buffer[1] !== 0x01) {
      throw new Error(`Unsupported Fingerprint Type: ${fingerprint}`);
    }

    return new X25519KeyAgreementKey2020({
      publicKeyMultibase: _multibaseEncode({bytes: buffer.slice(2)})
    });
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {LDKeyPair} options.publicKey - Remote key pair.
   *
   * @returns {string} Derived secret.
   */
  async deriveSecret({publicKey}) {
    const remotePublicKey = _multibaseDecode({
      text: publicKey.publicKeyMultibase
    });
    const privateKey = _multibaseDecode({
      text: this.privateKeyMultibase
    });

    return deriveSecret({privateKey, remotePublicKey});
  }

  /**
   * Generates and returns a multiformats encoded
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    const {publicKeyMultibase} = this;
    return X25519KeyAgreementKey2020
      .fingerprintFromPublicKey({publicKeyMultibase});
  }

  /**
   * Tests whether the fingerprint was generated from a given key pair.
   *
   * @example
   * xKeyPair.verifyFingerprint('...');
   * // {valid: true};
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.fingerprint - A multiformat encoded fingerprint.
   *
   * @returns {object} An object indicating valid is true or false.
   */
  verifyFingerprint({fingerprint} = {}) {
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false
      };
    }
    let fingerprintBytes;
    try {
      fingerprintBytes = _multibaseDecode({text: fingerprint});
    } catch(e) {
      return {error: e, valid: false};
    }
    let publicKeyBytes;
    try {
      publicKeyBytes = _multibaseDecode({text: this.publicKeyMultibase});
    } catch(e) {
      return {error: e, valid: false};
    }
    // validate the first buffer multicodec bytes 0xec 0x01
    const valid = fingerprintBytes[0] === 0xec &&
      fingerprintBytes[1] === 0x01 &&
      publicKeyBytes.toString() === fingerprintBytes.slice(2).toString();
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }
    return {valid};
  }
}

X25519KeyAgreementKey2020.suite = SUITE_ID;
