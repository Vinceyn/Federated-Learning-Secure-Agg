/**
 * This file provides cryptographic utility functions
 */
const { subtle, getRandomValues } = require('crypto').webcrypto;
const gen = require('random-seed');

 
/**
 * Helper static class with crypto function
 */

class Helper {

    static ecdhKeyParams = {
        name: "ECDH",
        namedCurve: "P-521"
    }

    /**
     * Create a personal random number generator from a seed
     * @param {Number} seed 
     * @returns A seeded pseudo random generator
     */
    static getPRNGFromSeed(seed) {
        return gen.create(seed);
    }

    /**
     * Derive an AES-GCM 256 bits key from a public private ECDH pair
     * @param {subtle.CryptoKey} privateKey 
     * @param {subtle.CryptoKey} publicKey 
     * @returns A 256 bits AES-GCM key
     */
    static async deriveEncryptionKey(privateKey, publicKey) {
        return await subtle.deriveKey(
            {
                name: "ECDH",
                public: publicKey
            },
            privateKey,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Derived an array of bits from an ECDH public and private key
     * @param {subtle.CryptoKey} privateKey 
     * @param {subtle.CryptoKey} publicKey 
     * @returns An array of bits
     */
    static async deriveSharedNumber(privateKey, publicKey) {

        const sharedNumber = await subtle.deriveBits(
            {
                name: "ECDH",
                namedCurve: "P-384",
                public: publicKey
            },
            privateKey,
            128
        );
        return sharedNumber
    }

    /**
     * Encrypt a message using AES GCM encryption
     * @param {subtle.CryptoKey} key 
     * @param {BufferSource} message 
     * @returns an ArrayBuffer containing the ciphertext
     */
    static async AESGCMEncrypt(key, message) {
        const encoder = new TextEncoder()
        let iv = getRandomValues(new Uint8Array(16));
        let encodedMessage = encoder.encode(message)
        const ciphertext = await subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encodedMessage
        );
        return { 'ciphertext': ciphertext, 'iv': iv }
    }

    /**
     * Decrypt a message using AES GCM decryption
     * @param {subtle.CryptoKey} key 
     * @param {BufferSource} ciphertext 
     * @param {typedArray} iv 
     * @returns The decrypted message
     */
    static async AESGCMDecrypt(key, ciphertext, iv) {
        const decrypted = await subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertext
        );
        const decoder = new TextDecoder()
        let message = decoder.decode(decrypted)
        return message
    }

}

module.exports = Helper