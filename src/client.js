/**
 * This file provides the client abstraction
 */

/**
 * Imports
 */
const { subtle } = require('crypto').webcrypto;
const gen = require('random-seed');
const { split } = require('shamir');
const { randomBytes } = require('crypto');
const Helper = require("./helper.js")


/**
 * Represents a client
 */
class Client {

    /**
     * Constructor of our client
     * @param {String} id Random ID designing the client
     * @param {Number} secretValue value representing the gradient
     * @param {Number} nbClients number of clients in the protocol
     * @param {Number} threshold threshold for shamir t out of n sharing
     */
    constructor(id, secretValue, nbClients, threshold) {
        this.id = id;
        this.secretValue = secretValue;
        this.nbClients = nbClients
        this.threshold = threshold;
        this.isUp = true;
    }


    /* ======== Round 0 ======== */


    /**
     * Generate ECDH keys for the encryption and for the Diffie Helmann seed agreement
     */
    async generateKeyPairs() {
        const ecdhKeyParams = Helper.ecdhKeyParams
        const seedKey = await subtle.generateKey(ecdhKeyParams, true, ["deriveKey", "deriveBits"]);
        this.seedPrivateKey = seedKey.privateKey;
        this.seedPublicKey = seedKey.publicKey;

        const encryptionKey = await subtle.generateKey(ecdhKeyParams, true, ["deriveKey", "deriveBits"]);
        this.encryptionPrivateKey = encryptionKey.privateKey;
        this.encryptionPublicKey = encryptionKey.publicKey;
    }

    /**
     * At round 0, the client generates its own key pairs and send it to the server
     * In our case, it's the server which fetches the public key pair from the client
     * @param {*} ecdh_params Parameters of the ECDH curve used to generate the keys
     */
    async round0(ecdh_params) {
        await this.generateKeyPairs(ecdh_params);
    }
 
 
 
    /* ======== Round 1 ======== */


    /**
     * Receive the clients from the server, verifies that there is no ID collision and that the number of Clients is higher than the threshold
     */
    async receiveClients(clientList) {

        if (clientList.length < this.threshold) {
            throw 'Not enough client for user ' + this.id + 'with only' + this.clientList.length + 'clients. Aborted.';
        }

        for (let i = 0; i < clientList.length; ++i) {
            for (let j = i + 1; j < clientList.length; ++j) {
                if (clientList[i].publicKey == clientList[j].publicKey) {
                    throw 'Collision between two public key pairs for client';
                }
            }
        }

        this.clientList = clientList
    }


    /**
     * Generate a random number which will be used to create the self mask
     */
    generateSelfMaskSeed() {
        const selfMaskSeed = gen.create()(2 ** 32);
        this.selfMaskSeed = selfMaskSeed;
    }


    /**
     * Generate shamir shares of the seed private key
     */
    async generateSecretKeyShares() {
        const utf8Encoder = new TextEncoder();
        const exportedKey = await subtle.exportKey("jwk", this.seedPrivateKey);
        const exportedKeyEncoded = utf8Encoder.encode(JSON.stringify(exportedKey));
        const secretKeyShamir = split(randomBytes, this.nbClients, this.threshold, exportedKeyEncoded);
        this.secretKeyShamir = secretKeyShamir;
    }

    /**
     * Generate shamir shares of the self mask seed
     */
    generateSelfMaskSeedShares() {
        const utf8Encoder = new TextEncoder();
        const secretKeyByte = utf8Encoder.encode(this.selfMaskSeed);
        const selfMaskSeedShamir = split(randomBytes, this.nbClients, this.threshold, secretKeyByte);
        this.selfMaskSeedShamir = selfMaskSeedShamir;
    }


    /** 
     * Store the pairwise information with all clients. 
     * It creates the shared seed by deriving a shared number between its seed private key and the other client seed public key
     * This seed is used to create a Personalized Random number Generator
     * It also creates an AES Key with its encryption private key and the other client seed public key
     */
    async computePairwiseEncryption() {
        let clientList_ = {};
        for (const clientIteratedID in this.clientList) {
            if (clientIteratedID != this.id) {
                const seedPublicKey = this.clientList[clientIteratedID].seedPublicKey;
                const seedBuffer = await Helper.deriveSharedNumber(this.seedPrivateKey, seedPublicKey);
                const seed = new DataView(seedBuffer, 0).getInt16(1);
                const PRNG = Helper.getPRNGFromSeed(seed);

                const AESKey = await Helper.deriveEncryptionKey(this.encryptionPrivateKey, this.clientList[clientIteratedID].encryptionPublicKey);

                clientList_[clientIteratedID] = new ClientForClient(clientIteratedID, seedPublicKey, seed, AESKey, PRNG);
            }
        }
        
        this.clientList = clientList_;
    }

    /**
     * Generate the ciphertexts
     * The method firstly concatenates the emitting client ID, the receiving client ID, the private key share
     * as well as the self mask seed share, and the index
     * The index is necessary for the library to reconstruct the secret
     * The concatenation uses the character | as a separation
     * Then, the concatenation is stocked into the ciphertexts variable, that has as key the concatenation of 
     * the emitting client ID and the receiving client ID with the character | as a separation
     */
    async generateCiphertexts() {
        let ciphertexts = {};
        let index = 1;

        for (const clientIteratedID in this.clientList) {
            if (clientIteratedID != this.id) {
                const secret = `${this.id}|${clientIteratedID}|${this.secretKeyShamir[index]}|${this.selfMaskSeedShamir[index]}|${index}`;
                ciphertexts[`${this.id}|${clientIteratedID}`] = await Helper.AESGCMEncrypt(this.clientList[clientIteratedID].AESKey, secret);
            }
            index += 1
        }
        this.ownPrivateKeyShare = this.secretKeyShamir[index]
        this.ownSelfMaskSeedShare = this.selfMaskSeedShamir[index]
        this.ownIndex = index

        this.ciphertexts = ciphertexts;
    }

    /**
     * In the round 1, the client generates its self mask seed.
     * Then, it generates the shamir t out of n shares for its self mask seed and its secret key.
     * It also computes the pairwise seeds and encryption.
     * Then, it encrypts into ciphertexts the pairwise information
     */
    async round1() {
        if (this.isUp) {
            this.generateSelfMaskSeed();
            await this.generateSecretKeyShares();
            this.generateSelfMaskSeedShares();
            await this.computePairwiseEncryption();
            await this.generateCiphertexts();
        }
    }


    /* ======== Round 2 ======== */


    /**
     * The client receives the ciphertexts from the other clients. 
     * It checks that the number of ciphertexts is greater than the threshold
     * @param {Object} ciphertexts Ciphertexts sent  by the server
     */
    receiveCiphertexts(ciphertexts) {
        let count = 0;
        for (const clientsID in ciphertexts) {
            const clientID = clientsID.split("|")[0];
            this.clientList[clientID].ciphertext = ciphertexts[clientsID];
            count += 1;
        }

        // Delete clients in U1 but not in U2
        this.clientListU2 = this.clientList // Pass by reference, but at least the variable has another name

        for (const clientIteratedID in this.clientList) {
            if (!this.clientList[clientIteratedID].hasOwnProperty('ciphertext')) {
                delete this.clientListU2[clientIteratedID]
            }
        }

        if (count < this.threshold - 1) {
            throw 'Not enough ciphertexts for user ' + this.id + ' with only ' + count + ' ciphertexts received for a threshold of ' + this.threshold;
        }
    }
 
     /**
      * Computes the masked input vector, putting pairwise masks or self mask depending on the client ID
      */
     computeMaskedInputVector() {

        const buffer = new ArrayBuffer(4)
        const view = new DataView(buffer)
        view.setInt32(0, 0)

        for (const clientIteratedID in this.clientListU2) {
            const mask = this.clientList[clientIteratedID].PRNG(2**32);
            if (clientIteratedID < this.id) {
                view.setInt32(0, view.getInt32(0) + mask);
            } else if (clientIteratedID > this.id) {
                view.setInt32(0, view.getInt32(0) - mask);
            }
        }

        const secretValueRounded = Number.parseInt(this.secretValue.toFixed(4) * (10**4))
        view.setInt32(0, view.getInt32(0) + secretValueRounded);

        const buffer2 = new ArrayBuffer(4)
        const view2 = new DataView(buffer2)
        view2.setInt32(0, secretValueRounded);

        const selfMask = gen.create(this.selfMaskSeed)(2 ** 32);
        view.setInt32(0, view.getInt32(0) + selfMask);

        const maskedGradient = Number.parseInt(view.getInt32(0))
        this.maskedGradient = maskedGradient;
    }
     
     /**
      * Represents the second round of the client. At this point, it only computes the masked input vector.
      */
     round2() {
         if (this.isUp) {
            this.computeMaskedInputVector();
         }
     }
 

    /* ======== Round 3 ======== */


    /**
     * Receive the list of clients remaining.
     * Checks there are more clients remaining than the threshold.
     * Then, check than the clients remaining ID were in the previous round.
     * At the end, it also creates the list of the clients that were lost during the round.
     * @param {Array} clientIDsU3 array of the ID of the remaining clients
     */
    receiveclientIDsU3(clientIDsU3) {

        if (clientIDsU3.length < this.threshold) {
            throw 'Only ' + clientIDsU3.length + ' clients up for threshold of ' + this.threshold + ' for user ' + this.id;
        }
        
        this.clientIDsU2 = Object.keys(this.clientListU2)
        this.clientIDsU3 = JSON.parse(JSON.stringify(clientIDsU3)); // Deep copy to not have any reference

        const IDsInU3NotinU2 = this.clientIDsU3.filter(key => !this.clientIDsU2.includes(key))
        
        /* The length should be 1: All client IDs in U3 should be part of U2 except the current client ID.
        If it is not the case, throw an error*/
        if (IDsInU3NotinU2.length > 1) {
            throw `For user ID ${this.id}, there are IDs received for U3 that are not part of U2. These IDs are: ${IDsInU3NotinU2}. Note: The own ID is in the list, it's normal. We should focus on the other IDs.`
        }

        this.IDsinU2NotInU3 = this.clientIDsU2.filter(key => !this.clientIDsU3.includes(key))
    }
 
    /**
     * Decrypt the ciphertext then store the important information to send them later.
     * The important information is the key shares for the dropped users, or the self mask seed share for the remaining users
     */
    async decryptCiphertext() {

        let splits = {}
        for (const clientIteratedID in this.clientListU2) {
            if (clientIteratedID != this.id) {
                const ciphertext = this.clientList[clientIteratedID].ciphertext
                const decoded = await Helper.AESGCMDecrypt(this.clientList[clientIteratedID].AESKey, ciphertext['ciphertext'], ciphertext['iv'])
                const correctCipher = decoded.split("|")
                const u = correctCipher[0]
                const v = correctCipher[1]
                const keySplit = correctCipher[2]
                const seedSplit = correctCipher[3]
                const index = correctCipher[4]
                if (u != clientIteratedID) {
                    throw 'Client ' + this.id + "| Error in decryptCiphertext: metadata for ciphertext sender is " + clientIteratedID + "while the encrypted ID of the sender is " + u
                }

                if (v != this.id) {
                    throw 'Client ' + this.id + "| Error in decryptCiphertext: the ciphertext should have been sent to " + v + " and not this client"
                }

                if (this.clientIDsU3.includes(clientIteratedID)) {
                    splits[clientIteratedID] = { 'seedSplit': seedSplit, 'index': index }
                }
                else {
                    splits[clientIteratedID] = { 'keySplit': keySplit, 'index': index }
                }
            }
        } 
        splits[this.id] = {'seedSplit': this.ownSelfMaskSeedShare.toString(), 'index': this.ownIndex}
        this.splits = splits
    }

    /**
     * Decrypt the ciphertext and send the seed share
     */
    async round3() {
        if (this.isUp) {
            await this.decryptCiphertext()
        }
    }

    /**
     * Drop down an user
     */
    putDown() {
        this.isUp = false;
    }
}

/**
 * Data Storing class representing the clients in a client
 */
class ClientForClient {
    constructor(id, seedPublicKey, seed, AESKey, PRNG) {
        this.id = id
        this.seedPublicKey = seedPublicKey
        this.seed = seed
        this.AESKey = AESKey
        this.PRNG = PRNG;
    }
}

module.exports = Client;