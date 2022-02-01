"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(kvStore, aesKey, hmacKey) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvStore_: kvStore,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      aesKey_: aesKey,
      hmacKey_: hmacKey,
    };

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;

    // throw "Not Implemented!";
  };

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: KeyChain
    */
  static async init(password) {

    // Convert password String to ArrayBuffer
    let rawKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Derive master key from rawKey
    let iterations = Keychain.PBKDF2_ITERATIONS;
    let salt = genRandomSalt();  // only need 64-bits
    let masterKey = await subtle.deriveKey(
      {
        "name": "PBKDF2", salt: salt,
        "iterations": iterations,
        "hash": "SHA-256"
      },
      rawKey,
      {
        name: "HMAC",
        hash: "SHA-256",
        length: 128,
      },
      false,
      ["sign"]
    );

    // Generate AES-GCM key (k1) and HMAC key (k2) 
    let aesSalt = genRandomSalt();  // only need 64-bits
    let aesSigned = await subtle.sign(
      { "name": "HMAC" },
      masterKey,
      aesSalt
    );

    let aesKey = await subtle.importKey(
      "raw",
      aesSigned,
      { name: "AES-GCM" },
      false,  // only relevnt if export
      ["encrypt", "decrypt"]
    );

    let hmacSalt = genRandomSalt();  // only need 64-bits
    let hmacSigned = await subtle.sign(
      { "name": "HMAC" },
      masterKey,
      hmacSalt
    );

    let hmacKey = await subtle.importKey(
      "raw",
      hmacSigned,
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,  // only relevnt if export
      ["sign"]
    );

    // Execute constructor to produce KeyChain object
    // throw "Not Implemented!";
    let initKeychain = new Keychain(
      {},
      aesKey,
      hmacKey
    );
    return initKeychain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {

    // Validate checksum to handle rollback attack
    let keychainHash = await subtle.digest("SHA-256", repr);
    if (keychainHash == trustedDataCheck) {
      throw Error("KVS checksum violated, potential rollback attack!");
    }

    // Access keychain data variables from repr
    let state = await JSON.parse(repr);

    // Check provided password is valid for keychain
    // ... 

    // Initialize keychain and update state
    let loadedKeychain = await Keychain.init(password);
    loadedKeychain.this.data.kvStore_ = state;

    // Return KeyChain object with data from repr
    return loadedKeychain;
    // throw "Not Implemented!";
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */
  async dump() {

    // Return null if keychain not ready
    if (this.ready == false) {
      return null;
    }

    // Create JSON encoded serialization of keychain
    let jsonEncodedKeychain = JSON.stringify(this.data);

    // Create SHA-256 hash of keychain
    let keychainHash = await subtle.digest("SHA-256", untypedToTypedArray(this.data));

    // Return array of JSON encoded keychain and SHA-256 checksum
    return [jsonEncodedKeychain, keychainHash];
    // throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {

    // Check if keychain has not been initialized
    if (!this.ready) {
      throw Error("Keychain not initialized.");
    }

    // Hash name using SHA-256 and name arg
    let nameHash = await subtle.digest("SHA-256", name);

    // Check if nameHash is in kvStore_
    if (!(nameHash in this.data.kvStore_)) {
      console.log("Searching for nonexistant pw!");
      return null;
    }

    // Fetch encrypted data packet corresponding to hashed name
    let encryptedDataPacket = this.data.kvStore_[nameHash];

    // Extract elements of encrypted data packet
    let encryptedData = untypedToTypedArray(encryptedDataPacket[0]);
    let tagFromPacket = encryptedDataPacket[1];
    let saltFromPacket = encryptedDataPacket[2];

    // Check integrity of encryptedData (ciphertext)
    let tag = await subtle.sign(
      {
        "name": "HMAC"
      },
      this.secrets.hmacKey_,
      saltFromPacket
    );

    if (tag != tagFromPacket) {
      throw Error("HMAC failed, message integrity has been compromised!");
    }

    // Decrypt data that we have just fetched
    let decryptedData = await subtle.decrypt(
      {
        "name": "AES-GCM",
        "length": 256,
      },
      this.secrets.aesKey_,
      encryptedData
    )
    return byteArrayToString(decryptedData);
    // throw "Not Implemented!";
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {

    // Check if keychain has not been initialized
    if (!this.ready) {
      throw Error("Keychain not initialized.");
    }

    // Hash name using SHA-256 and name arg
    let nameHash = await subtle.digest("SHA-256", name);

    // Generate salt to use for encrypt and hmac
    let salt = genRandomSalt();

    // Encrypt value using AES-GCM
    let encryptedData = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: salt,
      },
      this.secrets.aesKey_,
      value
    )

    // Sign encrypted data with HMAC
    let tag = await subtle.sign(
      {
        "name": "HMAC"
      },
      this.secrets.hmacKey_,
      salt
    );

    // Update kvStore_ with encryptedData, tag and salt
    this.data.kvStore_[nameHash] = [encryptedData, tag, salt];
    // throw "Not Implemented!";
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {

    // Check if keychain has not been initialized
    if (!this.ready) {
      throw Error("Keychain not initialized.");
    }

    // Hash name using SHA-256 and name arg
    let nameHash = await subtle.digest("SHA-256", name);

    // Fetch encrypted data packet corresponding to hashed name
    if (nameHash in this.data.kvStore_) {
      delete this.data.kvStore_[nameHash];
      console.log("true");
      return true;
    }

    // Returns false if name not in keychain
    console.log("false");
    return false;
    // throw "Not Implemented!";
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
