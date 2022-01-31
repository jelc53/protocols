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
  constructor(kvStore, initSalts, aesKey, hmacKey) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      initSalts_: initSalts,
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
    let masterSalt = genRandomSalt();  // only need 64-bits
    let masterKey = await subtle.deriveKey(
      {
        "name": "PBKDF2",
        salt: masterSalt,
        "iterations": iterations,
        "hash": "SHA-256"
      },
      rawKey,
      {
        "name": "AES-GCM",
        "length": 256,
      },
      false,
      ["encrypt", "decrypt"]
    );

    // Generate AES-GCM key (k1) and HMAC key (k2) 
    // let aesSalt = genRandomSalt(8);  // only need 64-bits
    let aesKey = await subtle.sign({ "name": "HMAC" }, masterKey, masterSalt);

    // let hmacSalt = genRandomSalt(8);  // only need 64-bits
    let hmacKey = await subtle.sign({ "name": "HMAC" }, masterKey, masterSalt);

    // Execute constructor to produce KeyChain object
    // throw "Not Implemented!";
    let initKeychain = new Keychain(
      {},
      [masterSalt, aesSalt, hmacSalt],
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

    // Access keychain data variables from repr
    // let state = await JSON.parse(repr[0]);

    // Check provided password is valid for keychain
    // ...

    // Validate checksum to handle rollback attack
    // if (trustedDataCheck == repr[1]) {
    //   throw "KVS checksum violated, potential rollback attack!";
    // }

    // Return KeyChain object with data from repr
    throw "Not Implemented!";
    // return Keychain();
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
    // ...

    // Create JSON encoded serialization of keychain
    // let jsonEncodedKeychain = JSON.stringify(this.data);

    // Create SHA-256 hash of keychain
    // let keychainHash = await subtle.digest("SHA-256", this.data);

    // Return array of JSON encoded keychain and SHA-256 checksum
    // return [jsonEncodedKeychain, keychainHash];
    throw "Not Implemented!";
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
    // throw "Keychain not initialized.";

    throw "Not Implemented!";
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
    // throw "Keychain not initialized.";

    throw "Not Implemented!";
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
    // throw "Keychain not initialized.";

    throw "Not Implemented!";
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
