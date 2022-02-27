"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  HKDF, // async
  HMACtoHMACKey, // async
  HMACtoAESKey, // async
  encryptWithGCM, // async
  decryptWithGCM, // async
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
} from "./lib";

/********* Implementation ********/

/** Stringify certificate for use in verification */
const stringifyCert = function (cert) {
  if (typeof cert == "object") {
    return JSON.stringify(cert);
  } else if (typeof cert == "string") {
    return cert;
  } else {
    throw "Certificate is not a JSON or string";
  }
};

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)
    
    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.me = {}; // stores secret and public keys for alice
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
  };

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {

    // Generate and store ElGamal key pair
    let keypairObject = await generateEG();
    this.me = keypairObject;
    
    // Construct and store certificate
    const certificate = {
      "issuer": "Certificate Auth",
      "expiry": "01/01/2023",
      "username": username,
      "pub": keypairObject.pub
    };

    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {

    // Generate HMAC of certificate
    let tag = HMACtoHMACKey(this.caPublicKey, stringifyCert(certificate))

    // Verify certificate and add to repo
    if (verifyWithECDSA(this.caPublicKey, tag, signature)) {
      this.certs[certificate.username] = certificate;
    } else {

      // Throw exception for potential tampering
      throw ("Certificate signature cannot be verified");
    }
  }

  /** 
   * Helper function to initialize the sender 
   * essentially performs Diffie-Helman ratchet
   *  
   * @pre Assume Alice and Bob both have generated 
   * certificates and that Alice has recewived Bob's
  */
  async initSender(name) {

    // Create shared secret to use as root key
    let sharedSecret = await computeDH(this.me.sec, this.certs[name].pub);

    // Generate Alice's Diffie-Helman pair for this connection
    let keypairObject = await generateEG();

    // Perform Diffie-Helman with Alice's private, Bob's public key 
    let DHOutput = await computeDH(keypairObject.sec, this.certs[name].pub);

    // Ratchet root chain by one step with sharedSecret (rk) as salt
    let [rootkey, chainkey] = await HKDF(DHOutput, sharedSecret, "ratchet-str");

    // Add Bob to list of active connections
    this.conns[name] = { 
      "pub": this.certs[name].pub,
      "root": rootkey,    // replaces original root key (sharedSecret)
      "chain": chainkey,  // to be replaced during symm ratchet
      // "msgkey": "",    // generated in symm ratchet, no need to store
    }

  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  async sendMessage(name, plaintext) {

    // Check if name initialized
    if (!(name in this.conns)) {
      console.log("running init sender sub-routine");
      this.initSender(name);
    }

    // Symmetric key ratchet
    let chainkey = await HMACtoHMACKey(this.conns[name].chain, "0");
    let msgkey = await HMACtoAESKey(this.conns[name].chain, "1", false)

    // Update bob's connection info
    this.conns[name].chain = chainkey;

    // Symmetric encryption of plaintext
    let iv = genRandomSalt();
    const ciphertext = await encryptWithGCM(msgkey, plaintext, iv);

    // Prepare header with everything needed for bob to decrypt and ratchet
    const header = {
      "iv": iv,
      "username": name,
      "pub": this.conns[name].pub,
    };

    return [header, JSON.stringify(ciphertext)];
  }

  /** Helper function to initialize the receiver */
  async initReceiver() {
    // do something ...
    return;
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  async receiveMessage(name, [header, ciphertext]) {

    // Check if name initialized
    if (!(name in this.conns)) {
      console.log("running init receiver sub-routine");
      this.initReceiver(name);
    }

    // Check if Bob's public key has changed
    if (header.pub != this.conns[name].pub) {
      // do something ...
    }

    throw ("not implemented!");
    return plaintext;
  }
};
