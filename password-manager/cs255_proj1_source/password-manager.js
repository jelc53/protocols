"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
const hmacPhrase = "HMAC_PHRASE";
const aesgcmPhrase = "AESGCM_PHRASE";
const masterPasswordPhrase = "MASTER_PW_PHRASE";

class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(salt, hmacKey, aesKey, masterPasswordPhraseSigned) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvs: {},
      salt: salt,
      hmacPhrase: hmacPhrase,
      aesgcmPhrase: aesgcmPhrase,
      masterPasswordPhrase: masterPasswordPhrase,
      masterPasswordPhraseSigned: masterPasswordPhraseSigned,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      hmacKey: hmacKey,
      aesKey: aesKey,
    };

    this.data.version = "CS 255 Password Manager v1.0";
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;

    // throw "Not Implemented!";
  };

  static async get_master_key(password, salt) {

    // Convert password String to ArrayBuffer
    let rawKey = await subtle.importKey(
      "raw",
      password,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Derive master key from rawKey
    salt = salt || genRandomSalt();
    let iterations = this.PBKDF2_ITERATIONS;
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

    return [salt, masterKey];

  }

  static async get_hmac_and_aes_keys(masterKey) {

    let hmacRawKey = await subtle.sign(
      "HMAC",
      masterKey,
      hmacPhrase
    );

    let hmacKey = await subtle.importKey(
      "raw",
      hmacRawKey,
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

    let aesRawKey = await subtle.sign(
      "HMAC",
      masterKey,
      aesgcmPhrase
    );

    let aesKey = await subtle.importKey(
      "raw",
      aesRawKey,
      { name: "AES-GCM", },
      false,
      ["encrypt", "decrypt"]
    );

    return [hmacKey, aesKey];

  }

  static async sign_master_password_phrase(masterKey) {

    let masterPasswordPhraseSigned = await subtle.sign(
      "HMAC",
      masterKey,
      masterPasswordPhrase
    );

    return untypedToTypedArray(masterPasswordPhraseSigned);

  }

  static async dict_to_unit8array(dic) {

    var dicValueArray = Object.keys(dic).map(function (key) {
      return dic[key];
    });

    return new Uint8Array(dicValueArray);

  }

  static async check_master_password_phrase(masterKey, masterPasswordPhraseSigned) {
    let validity = await subtle.verify(
      "HMAC",
      masterKey,
      await this.dict_to_unit8array(masterPasswordPhraseSigned),
      masterPasswordPhrase
    );

    return validity;

  }

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: KeyChain
    */
  static async init(password) {
    let [salt, masterKey] = await this.get_master_key(password);
    let [hmacKey, aesKey] = await this.get_hmac_and_aes_keys(masterKey);
    let masterPasswordPhraseSigned = await this.sign_master_password_phrase(masterKey);
    let pwdMngr = new Keychain(salt, hmacKey, aesKey, masterPasswordPhraseSigned);
    return pwdMngr;
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
    if (trustedDataCheck !== undefined) {
      const keychainHash = await subtle.digest("SHA-256", repr);
      if (byteArrayToString(keychainHash) !== trustedDataCheck) {
        throw "Trusted data check failed!";
      }
    }

    // Check whether salt name and value in repr
    let keychainDataPacket = JSON.parse(repr);
    if (!("salt" in keychainDataPacket) || (keychainDataPacket["salt"] == undefined)) {
      throw "Salt not found during load process."
    }

    // Rebuild keychain masterKey from password
    let [salt, masterKey] = await this.get_master_key(password, keychainDataPacket["salt"]);
    let masterPasswordPhraseSigned = keychainDataPacket["masterPasswordPhraseSigned"];

    // Check provided password is valid for keychain
    if (masterPasswordPhraseSigned == undefined || ! await this.check_master_password_phrase(masterKey, masterPasswordPhraseSigned)) {
      throw "Password is not valid for keychain!";
    }

    // Rebuild HMAC and AES keys from masterKey
    let [hmacKey, aesKey] = await this.get_hmac_and_aes_keys(masterKey);

    // Instantiate new password manager (Keychain)
    this.pwdMngr = new Keychain(salt, hmacKey, aesKey, masterPasswordPhraseSigned);
    this.pwdMngr.data = keychainDataPacket;

    return this.pwdMngr;

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

    // Check keychain is ready
    if (!this.ready) {
      return null;
    }

    // Create JSON encoded serialization of keychain
    const repr = JSON.stringify(this.data);

    // Create SHA-256 hash of keychain
    const trustedDataCheck = await subtle.digest("SHA-256", repr);

    // Return array of JSON encoded keychain and SHA-256 checksum
    return [repr, byteArrayToString(trustedDataCheck)];

  };

  async gen_name_hash(name) {

    // HMAC sign domain name
    let nameHash = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      name
    );

    return untypedToTypedArray(nameHash);

  }

  async encrypt_password(password) {

    // Generate salt to use for encrypt and hmac
    let iv = genRandomSalt(12);

    // Encrypt password using AES-GCM
    let encryptedPwd = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.secrets.aesKey,
      password
    );

    encryptedPwd = untypedToTypedArray(encryptedPwd);

    return [iv, encryptedPwd];

  }

  async decrypt_password(pwdDataPacket) {

    // Unpack password data
    let [iv, encryptedPwd] = pwdDataPacket;

    // Type conversion to enable sublte.decrypt()
    var encryptedPwdArray = Object.keys(encryptedPwd).map(function (key) {
      return encryptedPwd[key];
    });

    // Decrypt password using aesKey
    let password = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.secrets.aesKey,
      new Uint8Array(encryptedPwdArray)
    );

    return byteArrayToString(password);

  }

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

    // Check keychain is ready
    if (!this.ready) {
      throw "Keychain not initialized.";
    }

    // Generate name hash to match kvs storage
    let nameHash = await this.gen_name_hash(name);

    // Check if there exists data packet corresponding to name
    if (this.data.kvs[nameHash] == undefined) {
      return null;
    }

    return this.decrypt_password(this.data.kvs[nameHash]);

  }

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

    // Check keychain is ready
    if (!this.ready) {
      throw "Keychain not initialized.";
    }

    // Sign domain name with hmac key
    let nameHash = await this.gen_name_hash(name);

    // Generate encrypted password packet aes key
    let pwdDataPacket = await this.encrypt_password(value);

    // Update key value store
    this.data.kvs[nameHash] = pwdDataPacket;

  }

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

    // Check keychain is ready
    if (!this.ready) {
      throw "Keychain not initialized.";
    }

    // Sign domain name with hmacKey
    let nameHash = await this.gen_name_hash(name);

    // Check if domain name in keychain
    if (this.data.kvs[nameHash] !== undefined) {

      // Remove element from key-value pair from keychain
      delete this.data.kvs[nameHash];
      return true;
    }

    return false;

  }

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
