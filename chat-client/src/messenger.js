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

const infoStr = "ratchet-str"; // used for generating ratchet in HKDF
const data = "const_str"; // used for generating message key and next chain key

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
    // this.me = {}; // stores secret and public keys for alice
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
    this.sec = keypairObject.sec;
    this.pub = keypairObject.pub;
    
    // Construct and store certificate
    const certificate = {
      "issuer": "Certificate Auth",
      "expiry": "01/01/2023",
      "username": username,
      "pub": keypairObject.pub
    };
    this.cert = certificate;

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

    // Verify certificate and add to repo
    if (verifyWithECDSA(this.caPublicKey, stringifyCert(certificate), signature)) {
      this.certs[certificate.username] = certificate;
    } else {

      // Throw exception for potential tampering
      throw ("Certificate is invalid");
    }
  }

  /** 
   * Helper function to initialize the sender 
   *  
   * @pre Assume Alice and Bob both have generated 
   * certificates and that Alice has recewived Bob's
  */
  async initiateConn(certificate) {

    // Create shared secret to use as root key
    let sharedSecret = await computeDH(this.sec, certificate.pub);

    // Add Bob to list of active connections
    this.conns[certificate.username] = { 
      "self_pub": this.pub,         // store current version of alice's eg keypair
      "self_sec": this.sec,         // store current version of alice's eg keypair
      "root": sharedSecret,    // replaces original root key (sharedSecret)
      "conn_pub": certificate.pub,  // store bob's public key
      // "chain": chainkey,  // to be replaced during symm ratchet
      // "msgkey": "",    // generated in symm ratchet, no need to store
    }

  }

  /** 
   * Helper function to perform DH ratchet 
   * Implements HKDF as KDF function
   * */
  async ratchetRootChain(name, sendMessage=false) {

    // Create DH output to use as input key for root chain
    let dh_out = await computeDH(this.conns[name].self_sec, this.conns[name].conn_pub);

    // Execute HKDF to update root key and generate new chain key
    let [rootKey, chainKey] = await HKDF(dh_out, this.conns[name].root, infoStr);

    // Update connection information
    this.conns[name].root = rootKey;

    if (sendMessage) {
      this.conns[name].chain_send = await HMACtoHMACKey(chainKey, data);
    } 
    else {
      this.conns[name].chain_rec = await HMACtoHMACKey(chainKey, data);
    }
    
  }

  /** 
   * Helper function to support symmetric ratchet 
   * Implements HMAC as KDF function
  */
  async ratchetSymmChain(name, sendMessage=false) {
    
    if (sendMessage) {
      let prevChainKey = this.conns[name].chain_send;
      this.conns[name].chain_send = await HMACtoHMACKey(prevChainKey, data);
      this.conns[name].msgkey = await HMACtoAESKey(prevChainKey, data, false);
      this.conns[name].msgkey_arr = await HMACtoAESKey(prevChainKey, data, true);
    } 
    else {
      let prevChainKey = this.conns[name].chain_rec;
      this.conns[name].chain_rec = await HMACtoHMACKey(prevChainKey, data);
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

    // Check if bob (name) initialized
    if (!(name in this.conns)) {
      await this.initiateConn(this.certs[name]);
    }

    // Check if we have sent a message to bob (name) before
    if (!this.conns[name].chain_send) {
      await this.ratchetRootChain(name, true);
    }
    
    // Symmetric ratchet to increment chain and msg keys
    await this.ratchetSymmChain(name, true);
    let ivMsg = genRandomSalt();

    // Government surveillance
    let keypairObject = await generateEG();
    let vGov = keypairObject.pub;
    let dh_out = await computeDH(keypairObject.sec, this.govPublicKey);
    let govKey = await HMACtoAESKey(dh_out, "AES-gen");
    let ivGov = genRandomSalt();

   // Prepare header with everything needed for bob to decrypt and ratchet
   let header = {
    "ivMsg": ivMsg,
    "username": this.cert.username,
    "sender_pub": this.conns[name].self_pub,
    "vGov": vGov,
    "cGov": {},  // Need to stringify header for generating cGov
    "ivGov": ivGov,
    };

    // Symmetric encryption of plaintext
    const ciphertext = await encryptWithGCM(
      this.conns[name].msgkey, 
      plaintext, 
      ivMsg, 
      JSON.stringify(header)
    );
    
    // Update header with cGov
    const cGov = await encryptWithGCM(govKey, this.conns[name].msgkey_arr, ivGov);
    header.cGov = cGov;

    return [header, ciphertext];
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
      this.initiateConn(this.certs[name]);
    }

    // Check if received msg from this sender before
    // or, if public key of sender has been updated
    if (!this.conns[name].chain_rec || 
        header.sender_pub !== this.conns[name].conn_pub) {
      await this.ratchetRootChain(name, false);
    }
    else {
      await this.ratchetSymmChain(name, false);
    }

    // Decrypt ciphertext
    let plaintext = await decryptWithGCM(
      this.conns[name].msgkey, 
      ciphertext, 
      header.ivMsg, 
      JSON.stringify(header)
    );

    return byteArrayToString(plaintext);
  }
};
