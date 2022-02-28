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
    let keypairObject = await generateEG();
    this.eg_pub = keypairObject.pub;
    this.eg_sec = keypairObject.sec;
    const certificate = {
      "username": username,
      "eg_pub": this.eg_pub
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
    if (await verifyWithECDSA(this.caPublicKey, stringifyCert(certificate), signature)) {
      this.certs[certificate.username] = certificate;
    }
    else {
      throw "Certificate is invalid";
    }
  }

  async initiate_conn(certificate){
    this.conns[certificate.username] = {
      "root_key": await computeDH(this.eg_sec, certificate.eg_pub),
      "self_eg_pub": this.eg_pub,
      "self_eg_sec": this.eg_sec, 
      "other_eg_pub": certificate.eg_pub
    };
  }

  async advance_root_key(name, sendMessage=false) {

    let dh_out = await computeDH(this.conns[name].self_eg_sec, this.conns[name].other_eg_pub)
    let [new_root_key, chain_key] = await HKDF(dh_out, this.conns[name].root_key, infoStr);
    this.conns[name].root_key = new_root_key;
    if (sendMessage) {
      this.conns[name].chain_key_sen = await HMACtoHMACKey(chain_key, data);
    } else {
      this.conns[name].chain_key_rec = await HMACtoHMACKey(chain_key, data);
    }    

  }

  async advance_chain_key(name, sendMessage=false) {
    let dh_out = await computeDH(this.conns[name].self_eg_sec, this.conns[name].other_eg_pub)
    if (sendMessage) {
      let [new_chain_key, _] = await HKDF(dh_out, this.conns[name].chain_key_sen, infoStr);
      this.conns[name].chain_key_sen = await HMACtoHMACKey(new_chain_key, data);
    } else {
      let [new_chain_key, _] = await HKDF(dh_out, this.conns[name].chain_key_rec, infoStr);
      this.conns[name].chain_key_rec = await HMACtoHMACKey(new_chain_key, data);
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
    if (!(name in this.conns)) {
      await this.initiate_conn(this.certs[name]);
    }
    if (!this.conns[name].chain_key_sen) {
      await this.advance_root_key(name, true);
    } else {
      await this.advance_chain_key(name, true);
    }

    let msg_key = await HMACtoAESKey(this.conns[name].chain_key_sen, data, false);
    let msg_key_array = await HMACtoAESKey(this.conns[name].chain_key_sen, data, true);
    let receiver_iv = genRandomSalt();
    
    // goverment
    let keypairObject = await generateEG();
    let eg_pub = keypairObject.pub;
    let eg_sec = keypairObject.sec;
    let vGov = eg_pub;

    let dh_out = await computeDH(eg_sec, this.govPublicKey);
    let govKey = await HMACtoAESKey(dh_out, "AES-generation");
    let ivGov = genRandomSalt();

    let header = {
      "receiver_iv": receiver_iv,
      "username": this.cert.username,
      "eg_pub": this.conns[name].self_eg_pub,
      "vGov": vGov,
      "cGov": {}, // Need to JSON.stringify(header) for generating cGov, but cGov itself is included. Luckily it is not stringify-able
      "ivGov": ivGov
    }
    
    const ciphertext = await encryptWithGCM(msg_key, plaintext, receiver_iv, JSON.stringify(header));
    const cGov = await encryptWithGCM(govKey, msg_key_array, ivGov);

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
    if (!(name in this.conns)) {
      await this.initiate_conn(this.certs[name]);
    }

    if (!this.conns[name].chain_key_rec || header.eg_pub !== this.conns[name].other_eg_pub) {
      await this.advance_root_key(name, false);
    } else {
      await this.advance_chain_key(name, false);
    }

    let msg_key = await HMACtoAESKey(this.conns[name].chain_key_rec, data, false);
    let plaintext = await decryptWithGCM(msg_key, ciphertext, header.receiver_iv, JSON.stringify(header));
    return byteArrayToString(plaintext);
  }
};