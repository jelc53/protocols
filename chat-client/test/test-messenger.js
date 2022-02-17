"use strict";

import MessengerClient from "../messenger.js";
import {
  generateEG,
  computeDH,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA,
  HMACtoAESKey,
  byteArrayToString,
} from "../lib.js";

const { subtle } = require("crypto").webcrypto;

var chai = require("chai");
var chaiAsPromised = require("chai-as-promised");

chai.use(chaiAsPromised)
var expect = chai.expect;

const stringifyCert = function (cert) {
  if (typeof cert == "object") {
    return JSON.stringify(cert);
  } else if (typeof cert == "string") {
    return cert;
  } else {
    throw "Certificate is not a JSON or string";
  }
};

// Decrypt a message using the government secret key
const govDecrypt = async function (secret, [header, ct]) {
  // headers MUST have the field "vGov"!!!
  let govKey = await computeDH(secret, header.vGov);
  govKey = await HMACtoAESKey(govKey, "AES-generation");

  // headers MUST have the field "cGov" and "ivGov"!!!
  let mk = await decryptWithGCM(govKey, header.cGov, header.ivGov, JSON.stringify(header));
  let subtle_mk = await subtle.importKey("raw", mk, "AES-GCM", true, ["encrypt", "decrypt",]);

  let plaintext = await decryptWithGCM(subtle_mk, ct, header.receiver_iv, JSON.stringify(header));
  return byteArrayToString(plaintext);
};

describe("Messenger", function () {
  this.timeout(5000);

  describe("functionality", function () {
    let caKeyPair;
    let govKeyPair;

    before(async function () {
      // Key pair for the certificate certAuthority which will sign all certificates
      // generated by clients before relaying them to other clients
      caKeyPair = await generateECDSA();
      // keypair for the government to be able to decrypt all messages
      govKeyPair = await generateEG();
    });

    it('imports a certificate without an error', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
    });

    it('generates an encrypted message without error', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.sendMessage('bob', 'Hello, Bob');
    });

    it('bob can recieve an encrypted message from alice', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      const message = 'Hello, Bob'
      const ct = await alice.sendMessage('bob', message);
      const result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);
    });

    it('alice and bob can have a conversation', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);
      message = 'Hello, Alice'
      ct = await bob.sendMessage('alice', message);
      result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);
      message = 'Meet for lunch?'
      ct = await bob.sendMessage('alice', message);
      result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);
    });

    it('the government can decrypt an encrypted message from alice', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      const message = 'Hello, Bob'
      const ct = await alice.sendMessage('bob', message);
      const result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);
    });


    // // EXTENDED TEST CASES

    it('certificates with invalid signatures are rejected', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const bobCertificate = bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const invalidSignature = await signWithECDSA(caKeyPair.sec, "fake_signature");
      await expect(alice.receiveCertificate(bobCertificate, bobCertSignature)).to.not.be.rejected;
      await expect(alice.receiveCertificate(bobCertificate, invalidSignature)).to.be.rejected;
    }
    );

    it('message replay attacks are detected', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      await expect(bob.receiveMessage('alice', ct)).to.be.rejected;
    });

    it('alice rejects messages where she is not intended recipient', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await bob.receiveCertificate(claireCertificate, claireCertSignature);
      let message = 'Hello, Claire'
      let ct = await bob.sendMessage('claire', message);
      await expect(alice.receiveMessage('claire', ct)).to.be.rejected;
    });

    it('alice can send Bob a stream of messages with no response from Bob', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello Bob!'
      ct = await alice.sendMessage('bob', message);
      result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Are you even listening to me Bob?'
      ct = await alice.sendMessage('bob', message);
      result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'BOB ARE YOU LISTENING TO ME'
      ct = await alice.sendMessage('bob', message);
      result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);
    });

    it('alice can send Bob a stream of messages with infrequent responses from Bob', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);

      for (let i = 0; i < 2; i++) {
        for (let j = 0; j < 4; j++) {
          let message = 'message ' + j;
          let ct = await alice.sendMessage('bob', message);
          let result = await bob.receiveMessage('alice', ct);
          expect(result).to.equal(message);
        }
        let message = 'Roger ' + i
        let ct = await bob.sendMessage('alice', message);
        let result = await alice.receiveMessage('bob', ct);
        expect(result).to.equal(message);
      }
    });

    it('alice can receive multiple certificates without error', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));
      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
    });

    it('alice can send messages to multiple parties', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      await claire.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello, Claire'
      ct = await alice.sendMessage('claire', message);
      result = await claire.receiveMessage('alice', ct);
      expect(result).to.equal(message);
    });

    it('alice can receive messages from multiple parties', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      await claire.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello, Alice'
      let ct = await bob.sendMessage('alice', message);
      let result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await claire.sendMessage('alice', message);
      result = await alice.receiveMessage('claire', ct);
      expect(result).to.equal(message);
    });

    it('alice can initiate one conversation as first sender, another as first receiver', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      await claire.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await claire.sendMessage('alice', message);
      result = await alice.receiveMessage('claire', ct);
      expect(result).to.equal(message);
    });

    it('alice can have simultaneous and separate conversations with Bob, Claire, and Dave', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let dave = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));
      const daveCertificate = await dave.generateCertificate('dave');
      const daveCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(daveCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await alice.receiveCertificate(daveCertificate, daveCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      await claire.receiveCertificate(aliceCertificate, aliceCertSignature);
      await dave.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      let result = await bob.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello, Claire'
      ct = await alice.sendMessage('claire', message);
      result = await claire.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello, Dave'
      ct = await alice.sendMessage('dave', message);
      result = await dave.receiveMessage('alice', ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await bob.sendMessage('alice', message);
      result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await claire.sendMessage('alice', message);
      result = await alice.receiveMessage('claire', ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await dave.sendMessage('alice', message);
      result = await alice.receiveMessage('dave', ct);
      expect(result).to.equal(message);

      message = 'Meet for lunch?'
      ct = await bob.sendMessage('alice', message);
      result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);

      message = 'Meet for lunch?'
      ct = await claire.sendMessage('alice', message);
      result = await alice.receiveMessage('claire', ct);
      expect(result).to.equal(message);

      message = 'Meet for lunch?'
      ct = await dave.sendMessage('alice', message);
      result = await alice.receiveMessage('dave', ct);
      expect(result).to.equal(message);
    });

    it('the government can decrypt simultaneous conversations', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let claire = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let dave = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));
      const claireCertificate = await claire.generateCertificate('claire');
      const claireCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(claireCertificate));
      const daveCertificate = await dave.generateCertificate('dave');
      const daveCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(daveCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await alice.receiveCertificate(claireCertificate, claireCertSignature);
      await alice.receiveCertificate(daveCertificate, daveCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);
      await claire.receiveCertificate(aliceCertificate, aliceCertSignature);
      await dave.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message = 'Hello, Bob'
      let ct = await alice.sendMessage('bob', message);
      await bob.receiveMessage('alice', ct);
      let result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);

      message = 'Hello, Claire'
      ct = await alice.sendMessage('claire', message);
      await claire.receiveMessage('alice', ct);
      result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);

      message = 'Hello, Dave'
      ct = await alice.sendMessage('dave', message);
      await dave.receiveMessage('alice', ct);
      result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await bob.sendMessage('alice', message);
      await alice.receiveMessage('bob', ct);
      result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await claire.sendMessage('alice', message);
      await alice.receiveMessage('claire', ct);
      result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);

      message = 'Hello, Alice'
      ct = await dave.sendMessage('alice', message);
      await alice.receiveMessage('dave', ct);
      result = await govDecrypt(govKeyPair.sec, ct);
      expect(result).to.equal(message);
    });

    it('handles shuffled messages in single stream', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message1 = 'message 1'
      let ct1 = await alice.sendMessage('bob', message1);
      let message2 = 'message 2'
      let ct2 = await alice.sendMessage('bob', message2);
      let message3 = 'message 3'
      let ct3 = await alice.sendMessage('bob', message3);

      let result = await bob.receiveMessage('alice', ct1);
      expect(result).to.equal(message1);
      result = await bob.receiveMessage('alice', ct3);
      expect(result).to.equal(message3);
      result = await bob.receiveMessage('alice', ct2);
      expect(result).to.equal(message2);
    });

    it('handles messages where shuffling occurs around DH ratchet steps', async function() {
      let alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      let bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
      const aliceCertificate = await alice.generateCertificate('alice');
      const aliceCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(aliceCertificate));
      const bobCertificate = await bob.generateCertificate('bob');
      const bobCertSignature = await signWithECDSA(caKeyPair.sec, stringifyCert(bobCertificate));

      await alice.receiveCertificate(bobCertificate, bobCertSignature);
      await bob.receiveCertificate(aliceCertificate, aliceCertSignature);

      let message1 = 'message 1'
      let ct1 = await alice.sendMessage('bob', message1);
      let message2 = 'message 2'
      let ct2 = await alice.sendMessage('bob', message2);

      let result = await bob.receiveMessage('alice', ct1);
      expect(result).to.equal(message1);

      let message = 'DH ratchet'
      let ct = await bob.sendMessage('alice', message);
      result = await alice.receiveMessage('bob', ct);
      expect(result).to.equal(message);

      let message3 = 'message 3'
      let ct3 = await alice.sendMessage('bob', message3);

      result = await bob.receiveMessage('alice', ct3);
      expect(result).to.equal(message3);

      result = await bob.receiveMessage('alice', ct2);
      expect(result).to.equal(message2);
    });
  });
});
