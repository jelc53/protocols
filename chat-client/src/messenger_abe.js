"use strict";

/********* Imports ********/

const { subtle } = require("crypto").webcrypto;
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
    //printKey
  } from "./lib";

/********* Implementation ********/


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
	  this.publicEG;
      this.privateEG;
	  this.username;

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
    const certificate = {};
    var EG_pair = await generateEG();
	certificate['username'] = username;
    certificate['public'] = EG_pair.pub;
	this.publicEG = EG_pair.pub;
    this.privateEG = EG_pair.sec;
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
    let result = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature)
	if (result) this.certs[certificate['username']] = certificate;
	else throw Error("Invalid Cert!");
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
	// Brand new connection with dummy values
	if (!(name in this.conns)) {
		var certObj = this.certs[name];
	    var publicKey = certObj['public'];
		this.conns[name] = {
			"shared": publicKey,
			"RK": null,
			"CKs": null,
			"CKr": null,
			"EG": { pub: this.publicEG, sec: this.privateEG },
			"DHs": null
		}
    	var firstDH = await computeDH(this.privateEG, this.conns[name]["shared"]);
    	this.conns[name]["RK"] = await HMACtoHMACKey(firstDH, 'root');
	}
	// Increment Root Key and Increment Chain Key for first time
	if (this.conns[name]["CKs"] == null) {
		var newEGPair = await generateEG();
    	this.conns[name]["EG"] = newEGPair;
		var secondDH = await computeDH(this.conns[name]["EG"].sec, this.conns[name]["shared"]);
		var root_chain = await HKDF(this.conns[name]["RK"], secondDH, 'ratchet_root');
		this.conns[name]["RK"] = root_chain[0];
		this.conns[name]["CKs"] = root_chain[1];
	}
	// Increment Chain Key
	var currentChain = this.conns[name]["CKs"];
	let messageKeyHMAC = await HMACtoHMACKey(currentChain, 'msg1')
	var newIndividualMessageKey = await HMACtoAESKey(messageKeyHMAC, 'msg2', false);
  	var cksKey = await HMACtoHMACKey(this.conns[name]["CKs"], 'ratchet_symmetric');
	this.conns[name]["CKs"] = cksKey;

	// Government Encryption
    var ivGov = genRandomSalt();
    var govEG = await generateEG();
    var govDH = await computeDH(govEG.sec, this.govPublicKey);
    var govKey = await HMACtoAESKey(govDH, 'AES-generation');
    var messageForGovEncrypt = await HMACtoAESKey(messageKeyHMAC, 'msg2', true);
    const govEncryptedMessageKey = await encryptWithGCM(govKey, messageForGovEncrypt, ivGov);

	// Ciphertext IV
    var iv = genRandomSalt();

    const header = {
      "receiver_iv": iv,
      "vGov": govEG.pub,
      "cGov": govEncryptedMessageKey,
      "ivGov": ivGov,
	  "EG": this.conns[name]["EG"].pub,
    };

    const ciphertext = await encryptWithGCM(newIndividualMessageKey, plaintext, iv, JSON.stringify(header));

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
	// Brand new connection with dummy values
	if (!(name in this.conns)) {
  		var certObj = this.certs[name];
  	    var publicKey = certObj['public'];
  		this.conns[name] = {
  			"shared": publicKey,
  			"RK": null,
  			"CKs": null,
  			"CKr": null,
  			"EG": null,
  		}
      var firstDH = await computeDH(this.privateEG, this.conns[name]["shared"]);
      this.conns[name]["RK"] = await HMACtoHMACKey(firstDH, 'root');
      this.conns[name]["EG"] = { pub: this.publicEG, sec: this.privateEG };
  	}
	// Increment Root Key and Increment Chain Key for first time or if Public Key has changed
	if (this.conns[name]["CKr"] == null || this.conns[name]["shared"] != header["EG"]) {
		this.conns[name]["shared"] = header["EG"];
		var secondDH = await computeDH(this.conns[name]["EG"].sec, this.conns[name]["shared"]); // your own private key but other person's public key
    	var root_chain = await HKDF(this.conns[name]["RK"], secondDH, 'ratchet_root');
		this.conns[name]["RK"] = root_chain[0];
		this.conns[name]["CKr"] = root_chain[1];
	    this.conns[name]["EG"] = await generateEG();
	    var thirdDH = await computeDH(this.conns[name]["EG"].sec, this.conns[name]["shared"]); // your own private key but other person's public key
	    var root_chain2 = await HKDF(this.conns[name]["RK"], thirdDH, 'ratchet_root');
		this.conns[name]["RK"] = root_chain2[0];
		this.conns[name]["CKs"] = root_chain2[1];
	}
	var newIndividualMessageKey = await HMACtoAESKey(await HMACtoHMACKey(this.conns[name]["CKr"], 'msg1'), 'msg2', false);
	var ckrKey = await HMACtoHMACKey(this.conns[name]["CKr"], 'ratchet_symmetric');
	this.conns[name]["CKr"] = ckrKey;
	var plaintextArray = await decryptWithGCM(newIndividualMessageKey, ciphertext, header["receiver_iv"], JSON.stringify(header));
	var plaintext = byteArrayToString(plaintextArray);
	return plaintext;
 }

}