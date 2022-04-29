/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import {
  X25519KeyAgreementKey2019
} from '@digitalbazaar/x25519-key-agreement-key-2019';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {X25519KeyAgreementKey2020} from '../lib/index.js';
import {encode} from 'base58-universal';

const mockKey = {
  publicKeyMultibase: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  privateKeyMultibase: 'z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT'
};

describe('X25519KeyAgreementKey2020', () => {
  describe('class vars', () => {
    it('should expose suite and context for crypto-ld usage', async () => {
      expect(X25519KeyAgreementKey2020.suite)
        .to.equal('X25519KeyAgreementKey2020');
      expect(X25519KeyAgreementKey2020.SUITE_CONTEXT)
        .to.equal('https://w3id.org/security/suites/x25519-2020/v1');
    });
  });

  describe('constructor', () => {
    it('should auto-set key.id based on controller, if present', async () => {
      const {publicKeyMultibase} = mockKey;
      const controller = 'did:example:1234';

      const keyPair = new X25519KeyAgreementKey2020({
        controller, publicKeyMultibase
      });
      expect(keyPair.id).to.equal(
        'did:example:1234#' + keyPair.fingerprint());
    });

    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        new X25519KeyAgreementKey2020();
      } catch(e) {
        error = e;
      }
      expect(error.message)
        .to.equal('The "publicKeyMultibase" property is required.');
    });
  });

  describe('fromEd25519VerificationKey2020', () => {
    it('should convert both public and private key (2020)', async () => {
      const edKeyPair = await Ed25519VerificationKey2020.from({
        controller: 'did:example:123',
        publicKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
        privateKeyMultibase: 'zruzf4Y29hDp7vLoV3NWzuymGMTtJcQfttAWzESod4wV2fb' +
          'PvEp4XtzGp2VWwQSQAXMxDyqrnVurYg2sBiqiu1FHDDM'
      });

      const xKeyPair = X25519KeyAgreementKey2020
        .fromEd25519VerificationKey2020({keyPair: edKeyPair});

      expect(xKeyPair.type).to.equal('X25519KeyAgreementKey2020');
      expect(xKeyPair.controller).to.equal('did:example:123');
      expect(xKeyPair.publicKeyMultibase).to
        .equal('z6LSdVzMmB67tKXYmkjiKRAQgbxgjnjdfiajqUvx7C9fxTNv');
      expect(xKeyPair.privateKeyMultibase).to
        .equal('z3wecm2zNYbRorUz8ZfuV1tGbKr41xS2GzZM2jFfvyXytE9K');

      // Check to make sure export works after conversion
      const exported = xKeyPair.export({publicKey: true});

      expect(exported).to.have.any.keys(['publicKeyMultibase']);
      expect(exported).to.not.have.keys(['privateKeyMultibase']);
    });
  });

  describe('deriveSecret', () => {
    it('should produce a secret from a remote key', async () => {
      const localKey = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: 'z6LSdVzMmB67tKXYmkjiKRAQgbxgjnjdfiajqUvx7C9fxTNv',
        privateKeyMultibase: 'z3wecm2zNYbRorUz8ZfuV1tGbKr41xS2GzZM2jFfvyXytE9K'
      });

      const edKeyPair = await Ed25519VerificationKey2020.from({
        controller: 'did:example:123',
        publicKeyMultibase: 'z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T',
        privateKeyMultibase: 'zrv2EET2WWZ8T1Jbg4fEH5cQxhbUS22XxdweypUbjWVzv1Y' +
          'D6VqYuW6LH7heQCNYQCuoKaDwvv2qCWz3uBzG2xesqmf'
      });
      const remoteKey = X25519KeyAgreementKey2020
        .fromEd25519VerificationKey2020({keyPair: edKeyPair});

      const secret = await localKey.deriveSecret({publicKey: remoteKey});
      const secretString = encode(secret);

      expect(secretString).to
        .equal('4jK2aXkz6pspNahm7yvMS9Z8S1ghtDm22Q1HjE3p1cNJ');
    });
  });

  describe(`export`, () => {
    it('should export only the public key', async () => {
      const key = await X25519KeyAgreementKey2020.generate({
        controller: 'did:ex:1234'
      });

      const exported = key.export({publicKey: true});
      expect(exported).to.have.any.keys(['publicKeyMultibase']);
      expect(exported).to.not.have.keys(['privateKeyMultibase']);
    });

    it('should export only the private key', async () => {
      const key = await X25519KeyAgreementKey2020.generate();

      const exported = key.export({privateKey: true});
      expect(exported).to.not.have.keys(['publicKeyMultibase']);
      expect(exported).to.have.any.keys(['privateKeyMultibase']);
    });

    it('should export both public and private key', async () => {
      const key = await X25519KeyAgreementKey2020.generate({
        controller: 'did:example:1234'
      });
      const pastDate = new Date(2020, 11, 17).toISOString()
        .replace(/\.[0-9]{3}/, '');
      key.revoked = pastDate;

      const exported = key.export({publicKey: true, privateKey: true});
      expect(exported).to.have.keys([
        'id', 'type', 'controller', 'publicKeyMultibase',
        'privateKeyMultibase', 'revoked'
      ]);
      expect(exported.controller).to.equal('did:example:1234');
      expect(exported.type).to.equal('X25519KeyAgreementKey2020');
      expect(exported).to.have.property('revoked', pastDate);
    });
  });

  describe('fingerprint', () => {
    it('should round trip convert to and from public key', async () => {
      const key = await X25519KeyAgreementKey2020.generate();
      const fingerprint = key.fingerprint();
      const newKey = X25519KeyAgreementKey2020.fromFingerprint({fingerprint});

      expect(key.publicKeyMultibase).to.equal(newKey.publicKeyMultibase);
    });

    it('should verify via verifyFingerprint()', async () => {
      const key = await X25519KeyAgreementKey2020.generate();
      const fingerprint = key.fingerprint();

      const result = key.verifyFingerprint({fingerprint});
      expect(result.valid).to.be.true;
      expect(result.error).to.not.exist;
    });
  });

  describe('Backwards compat with X25519KeyAgreementKey2019', () => {
    it('2020 key should import from 2019', async () => {
      const keyPair2019 = await X25519KeyAgreementKey2019.generate({
        controller: 'did:example:1234'
      });

      const keyPair2020 = await X25519KeyAgreementKey2020
        .fromX25519KeyAgreementKey2019(keyPair2019);

      // Both should have the same fingerprint
      expect(keyPair2019.fingerprint()).to.equal(keyPair2020.fingerprint());
    });
  });
});
