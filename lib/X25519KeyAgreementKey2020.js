/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {LDKeyPair} from 'crypto-ld';
import ed2curve from 'ed2curve';
import * as base58btc from 'base58-universal';

import {generateKeyPair, deriveSecret} from './crypto.js';

const SUITE_ID = 'X25519KeyAgreementKey2020';

export class X25519KeyAgreementKey2020 extends LDKeyPair {
  /**
   * @param {object} options - Options hashmap.
   * @param {string} options.controller - Controller DID or document url.
   * @param {string} [options.id] - Key ID, typically composed of controller
   *   URL and key fingerprint as hash fragment.
   * @param {string} options.publicKeyMultibase - Multibase encoded public key.
   * @param {string} [options.privateKeyMultibase] - Multibase private key.
   */
  constructor(options = {}) {
    super(options);
    this.type = SUITE_ID;
    this.publicKeyMultibase = options.publicKeyMultibase;
    if(!this.publicKeyMultibase) {
      throw TypeError('The "publicKeyMultibase" parameter is required.');
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
    if(options.publicKeyBase58) {
      return this.fromX25519KeyAgreementKey2019(options);
    }
    return new X25519KeyAgreementKey2020(options);
  }

  /**
   * Creates an X25519KeyAgreementKey2020 Key Pair from an existing 2019 key
   * (backwards compatibility method).
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {string} options.publicKeyBase58 - Base58btc encoded public key.
   * @param {string} [options.privateKeyBase58] - Base58btc encoded private key.
   * @param {object} [options.keyPairOptions] - Other options.
   *
   * @returns {Promise<X25519KeyAgreementKey2020>} 2020 Crypto suite key pair.
   */
  static async fromX25519KeyAgreementKey2019({
    publicKeyBase58, privateKeyBase58, ...keyPairOptions
  } = {}) {
    let publicKeyMultibase, privateKeyMultibase;

    if(publicKeyBase58) {
      // prefix with `z` to indicate multi-base base58btc encoding
      publicKeyMultibase = `z${publicKeyBase58}`;
    }
    if(privateKeyBase58) {
      // prefix with `z` to indicate multi-base base58btc encoding
      privateKeyMultibase = `z${privateKeyBase58}`;
    }
    return new X25519KeyAgreementKey2020({
      publicKeyMultibase, privateKeyMultibase, ...keyPairOptions
    });
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
        // eslint-disable-next-line max-len
        'Expecting "publicKeyMultibase" value to be multibase base58btc encoded (must start with "z").'
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
          'Expecting "privateKeyMultibase" value to be multibase base58btc encoded (must start with "z").'
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
   * Generates and returns a base58btc multibase encoded value of a multicodec
   * X25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   * @see https://github.com/multiformats/multibase
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
    const publicKeyBytes = _multibaseDecode({text: publicKeyMultibase});
    // X25519 cryptonyms are multicodec formatted values, specifically:
    // (multicodec('x25519-pub') + key bytes)
    const fingerprintBytes = _multicodecFormatFingerprint({publicKeyBytes});
    const encodedFingerprint = _multibaseEncode({bytes: fingerprintBytes});

    return encodedFingerprint;
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
    const fingerprintBytes = _multibaseDecode({text: fingerprint});

    const publicKeyBytes = _multicodecDecodeFingerprint({
      bytes: fingerprintBytes
    });

    return new X25519KeyAgreementKey2020({
      publicKeyMultibase: _multibaseEncode({bytes: publicKeyBytes})
    });
  }

  /**
   * Derives a shared secret via a given public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather as an input into a key derivation function
   * (KDF) to produce a shared key.
   *
   * @param {object} [options={}] - Options hashmap.
   * @param {LDKeyPair} options.publicKey - Remote key pair.
   *
   * @returns {Promise<string>} Derived secret.
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
   * @param {string} options.fingerprint - An x25519 key fingerprint (typically
   *   from a key id).
   *
   * @returns {object} An object indicating valid is true or false.
   */
  verifyFingerprint({fingerprint} = {}) {
    // fingerprint should have `z` prefix indicating
    // that it's base58btc multibase encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        // eslint-disable-next-line max-len
        error: new Error('`fingerprint` must be a multibase base58btc encoded string (must start with a "z").'),
        valid: false
      };
    }

    let fingerprintBytes, fingerprintKeyBytes;
    try {
      fingerprintBytes = _multibaseDecode({text: fingerprint});
      fingerprintKeyBytes = _multicodecDecodeFingerprint({
        bytes: fingerprintBytes
      });
    } catch(e) {
      return {valid: false, error: new Error('Error decoding fingerprint.')};
    }
    const publicKeyBytes = _multibaseDecode({text: this.publicKeyMultibase});

    const valid = publicKeyBytes.toString() === fingerprintKeyBytes.toString();
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }
    return {valid: true};
  }
}

X25519KeyAgreementKey2020.suite = SUITE_ID;

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

/**
 * Returns raw fingerprint bytes, by adding a multicodec prefix for an
 * X25519 public key.
 *
 * @see https://github.com/multiformats/multicodec/blob/master/table.csv
 * 0xec is the value for X25519 public key
 * 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
 * @see https://github.com/multiformats/unsigned-varint
 *
 * @param {object} [options={}] - Options hashmap.
 * @param {Uint8Array} options.publicKeyBytes - Public key raw bytes.
 *
 * @returns {Uint8Array} Multicodec formatted public key fingerprint bytes.
 */
function _multicodecFormatFingerprint({publicKeyBytes} = {}) {
  const fingerprintBytes = new Uint8Array(2 + publicKeyBytes.length);
  fingerprintBytes[0] = 0xec;
  fingerprintBytes[1] = 0x01;
  fingerprintBytes.set(publicKeyBytes, 2);
  return fingerprintBytes;
}

/**
 * Decodes a multicodec-formatted Uint8Array containing an x25519 public key.
 *
 * @see https://github.com/multiformats/multicodec/blob/master/table.csv
 * 0xec is the value for X25519 public key
 * 0x01 is from varint.encode(0xec) -> [0xec, 0x01]
 * @see https://github.com/multiformats/unsigned-varint
 *
 * @param {object} [options={}] - Options hashmap.
 * @param {Uint8Array} options.bytes - Key fingerprint decoded from multibase.
 *
 * @returns {{publicKeyBytes: Uint8Array}} The public key bytes (without the
 *   multicodec prefix).
 */
function _multicodecDecodeFingerprint({bytes} = {}) {
  if(!(bytes && bytes[0] === 0xec && bytes[1] === 0x01)) {
    // eslint-disable-next-line max-len
    throw new Error('Expecting public key to be "x255519-pub" multicodec formatted [0xec, 0x01, <public key bytes>]');
  }
  // Remove the multicodec prefix
  const publicKeyBytes = bytes.slice(2);
  return publicKeyBytes;
}
