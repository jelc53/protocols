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

    // Generate El Gamal key pair
    let keypairObject = await generateEG();

    // Construct certificate
    const certificate = {
      issuer: "Certificate Auth",
      expiry: "01/01/2023",
      username: username,
      pub: keypairObject.pub,
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

    // Verify certificate and 
    if (verifyWithECDSA(this.caPublicKey, tag, signature)) {
      this.certs[certificate.username] = certificate;
    } else {

      // Throw exception for potential tampering
      throw ("Certificate signature cannot be verified");
    }
  }

  /** ... */
  // async initSender() {}

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
    throw ("not implemented!");
    const header = {};
    const ciphertext = "";
    return [header, ciphertext];
  }

  /** ... */
  // async initReceiver() {}

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
    throw ("not implemented!");
    return plaintext;
  }
};
