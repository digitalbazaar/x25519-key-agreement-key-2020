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
import {X25519KeyAgreementKey2020} from '../lib/index';
import {encode} from 'base58-universal';

const mockKey = {
  publicKeyMultibase: 'z3kG4YvxDhr7CYMfbevpXupxxBtVMdaw5XrMZPuEEpL6b',
  privateKeyMultibase: 'z8aEXQC89JZqrbYyVuufNAibQyXgsaGi8jaNL9vSPSc2H'
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
        .to.equal('The "publicKeyMultibase" parameter is required.');
    });
  });

  describe('fromEd25519VerificationKey2020', () => {
    it('should convert both public and private key (2020)', async () => {
      const edKeyPair = await Ed25519VerificationKey2020.from({
        controller: 'did:example:123',
        /* eslint-disable-next-line max-len */
        privateKeyMultibase: 'z4F71TAGqQYe7KE9p4HUzoVV9arQwKP4gPtvi89EPNGuwA1qLE4RRxitA2rEcdEszERj3pN1DWKARBZQ2BACLbW1V',
        publicKeyMultibase: 'zHLi1h9SzENZyEv7ifPNtu8xyJNzCFFeaC6X9rsZKFgv3'
      });

      const xKeyPair = X25519KeyAgreementKey2020
        .fromEd25519VerificationKey2020({keyPair: edKeyPair});

      expect(xKeyPair.type).to.equal('X25519KeyAgreementKey2020');
      expect(xKeyPair.controller).to.equal('did:example:123');
      expect(xKeyPair.publicKeyMultibase).to
        .equal('z9K6xjwBdjKC4W3r41ZP5WUxp8XXm8gT9GvR1G5Eocs1Z');
      expect(xKeyPair.privateKeyMultibase).to
        .equal('zH9ruaVs9LnRUwxNMLTjDkEbWW1P3bcBuiu7GxoBbEpdV');

      // Check to make sure export works after conversion
      const exported = xKeyPair.export({publicKey: true});

      expect(exported).to.have.any.keys(['publicKeyMultibase']);
      expect(exported).to.not.have.keys(['privateKeyMultibase']);
    });
  });

  describe('deriveSecret', () => {
    it('should produce a secret from a remote key', async () => {
      const localKey = await X25519KeyAgreementKey2020.from({
        privateKeyMultibase: 'zB1tfmsThxDBrFx7VdtimC26s1WW1aFySxdR16n5SfDJa',
        publicKeyMultibase: 'zFWzRdFAfTJGsdPWFvD1oXy469wAsGptMiFpdecxgcek6'
      });

      const remoteKey = await X25519KeyAgreementKey2020.from({
        publicKeyMultibase: 'z73e843su1epHouuHyDzjy2YXZfZrNiXLrr1hjpJkBeUG'
      });

      const secret = await localKey.deriveSecret({publicKey: remoteKey});
      const secretString = encode(secret);

      expect(secretString).to
        .equal('3orgcVQPH25E7ybPDz7eEnawCFTtjuYEu3nXQNPbQ1Sv');
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
