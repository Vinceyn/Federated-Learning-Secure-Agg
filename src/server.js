/**
 * This file provides the server abstraction
 */

/**
 * Imports
 */
const { subtle } = require('crypto').webcrypto;
const gen = require('random-seed');
const { join } = require('shamir');
const Client = require("./client.js")
const Helper = require("./helper.js")


/**
 * Represent a server
 */
 class Server {

    /**
     * Construct the clients
     * @param {Client} clients Clients to the server
     * @param {Number} nbClients Number of clients in the settings
     * @param {Number} threshold Shamir t out of n threshold
     */
    constructor(clients, nbClients, threshold) {
        this.clients = clients;
        this.nbClients = nbClients;
        this.threshold = threshold;
    }


    /* ======== Round 0 ======== */
    

    /**
     * Receive the public keys from the clients and put the information in a clientlist
     */
    async receivePublicKeys() {
        let clientList = {};
        for (let i = 0; i < this.clients.length; i++) {
            const id = this.clients[i].id;
            const seedPublicKey = this.clients[i].seedPublicKey;
            const encryptionPublicKey = this.clients[i].encryptionPublicKey;
            const client = new ClientForServer(this.clients[i], id, seedPublicKey, encryptionPublicKey);
            clientList[id] = client;
        }
        this.clientList = clientList;
    }

    /**
     * Broadcast the client informations to the clients
     */
    async broadcastClients() {
        for (const clientIteratedID in this.clientList) {
            await this.clientList[clientIteratedID].client.receiveClients(this.clientList);
        }
    }

    /**
     * In round 0, the server collects public information of individuals and broadcast it to the other clients
     */
    async round0() {
        await this.receivePublicKeys();
        await this.broadcastClients();
    }
    

    /* ======== Round 1 ======== */
    

    /**
     * Compute the list U2 of clients remaining when the server will collect the ciphertext
     */
    computeU2() {
        this.clientListU2 = this.clientList // Pass by reference, but at least the variable has another name
        for (const clientIteratedID in this.clientList) {
           if (!this.clientList[clientIteratedID].client.isUp) {
               delete this.clientListU2[clientIteratedID]
           }
        }

        if (this.clientListU2.length < this.threshold) {
            throw 'Only ' + this.clientListU2.length + ' clients up for threshold of ' + this.threshold + ' for server at the end of round 1 for U2';
        }
    }

    /**
     * Collect the ciphertexts from the clients in U2 and store them
     */
    collectCiphertexts() {
        /* Fetch from clients the ciphertext*/
        let ciphertextStorer = {}
        for (const clientIteratedID in this.clientListU2) {
            const ciphertextsFromID = this.clientListU2[clientIteratedID].client.ciphertexts
            ciphertextStorer[clientIteratedID] = ciphertextsFromID
        }
         
        let clientCiphertextBuffer = {}

        /* Create a data structure to sort the ciphertexts */
        for (const clientIDOuter in this.clientListU2) {
            let clientOuterBuffer = {}
            for (const clientIDInner in this.clientListU2) {
                if (clientIDOuter != clientIDInner) {
                    const ciphertextsFromInner = ciphertextStorer[clientIDInner]
                    const desiredProperty = `${clientIDInner}|${clientIDOuter}`
                    clientOuterBuffer[desiredProperty] = ciphertextsFromInner[desiredProperty]
                }
            }
            clientCiphertextBuffer[clientIDOuter] = clientOuterBuffer
        }
        
        this.clientCiphertextBuffer = clientCiphertextBuffer
    }
 
    /**
     * Send the ciphertexts to the corresponding clients in U2
     */
    sendCiphertexts() {
        for (const clientIteratedID in this.clientCiphertextBuffer) {
            this.clientListU2[clientIteratedID].client.receiveCiphertexts(this.clientCiphertextBuffer[clientIteratedID])
        }
    }

    /**
     * Collect the ciphertext and send them
     */
    async round1() {
        this.computeU2()
        this.collectCiphertexts()
        this.sendCiphertexts()
    }


    /* ======== Round 2 ======== */
    

    /**
     * Compute the list U3 of the clients that have sent their gradients.
     * Compute the list of clients that have sent their ciphertexts and public keys but
     */
    computeU3() {
        this.clientIDsU2 = Object.keys(this.clientListU2)
        this.clientIDsU3 = []

        for (const clientIteratedID in this.clientListU2) {
           if (this.clientListU2[clientIteratedID].client.isUp) {
               this.clientIDsU3.push(this.clientListU2[clientIteratedID].id)
           }
        }
        this.clientU2NotInU3 = this.clientIDsU2.filter(key => !this.clientIDsU3.includes(key))

        if (this.clientIDsU3.length < this.threshold) {
            throw 'Too many clients are down in Round 2 server Aggregation - We are not able to aggregate'
        }
    }

    /**
     * Collect the masked gradient by averaging the ones from clients remaining in U3
     * @returns masked gradient average
     */
    collectMaskedGradient() {
         
        const buffer = new ArrayBuffer(4)
        const view = new DataView(buffer)
        view.setInt32(0, 0)

        for (const clientIteratedID in this.clientListU2) {
            if (this.clientIDsU3.includes(clientIteratedID)) {
                    const clientIteratedMaskedGradient = this.clientList[clientIteratedID].client.maskedGradient;
                    view.setInt32(0, view.getInt32(0) + clientIteratedMaskedGradient)
                }
            }
            
        this.agg = Number.parseInt(view.getInt32(0))
    }
 
    /**
     * Send the list of remaining clients to the remaining clients
     */
    sendClientIDsU3() {
        for (const clientIteratedID in this.clientListU2) {
            if (this.clientIDsU3.includes(clientIteratedID)) {
                this.clientList[clientIteratedID].client.receiveclientIDsU3(this.clientIDsU3)
            }
        }
    }

    /**
     * In round 2, the server collects the masked gradients and keep track of the remaining clients
     * Then, it sends the list of remaining clients to the remaining clients
     */
    round2() {
        this.computeU3()
        this.collectMaskedGradient()
        this.sendClientIDsU3()
    }
 

    /* ======== Round 3 ======== */
    

    /**
     * Compute U5, the set of clients that have sent their shares to the server
     */
    computeU5() {
        this.clientIDsU5 = []

        for (const clientIteratedID in this.clientListU2) {
            if (this.clientListU2[clientIteratedID].client.isUp) {
                this.clientIDsU5.push(this.clientListU2[clientIteratedID].id)
            }
        }

        if (this.clientIDsU5.length < this.threshold) {
            throw 'Too many clients dropped in Round 4 server Aggregation - We are not able to aggregate'
        }
    }

    /**
     * Collect the ciphertexts corresponding of the remaining clients
     * Sort them depending if the client is alive or not
     */
    collectResponses() {
        let keyStocker = {};
        let seedStocker = {};

        for (let i = 0; i < this.clientIDsU5.length; ++i) {

            const clientAliveID = this.clientIDsU5[i]

            keyStocker[clientAliveID] = {}
            seedStocker[clientAliveID] = {}
            for (const clientIteratedID in this.clientListU2) {
                if (this.clientU2NotInU3.includes(clientIteratedID)) {
                    keyStocker[clientAliveID][clientIteratedID] = this.clientListU2[clientAliveID].client.splits[clientIteratedID];
                }
                else {
                    seedStocker[clientAliveID][clientIteratedID] = this.clientListU2[clientAliveID].client.splits[clientIteratedID];
                }
            }
        }

        this.keyStocker = keyStocker
        this.seedStocker = seedStocker
    }

    /**
     * Reconstruct the keys of the clients that dropped at U3
     */
    async reconstructDroppedClientsKeys() {
        let keysRetrieved = {};

        for (let i = 0; i < this.clientU2NotInU3.length; ++i) {
            const clientDroppedID = this.clientU2NotInU3[i];
            let keyShamirRecover = {}
            for (const clientAliveIteratedID in this.keyStocker) {
                keyShamirRecover[this.keyStocker[clientAliveIteratedID][clientDroppedID]['index']] = this.keyStocker[clientAliveIteratedID][clientDroppedID]['keySplit'].split(",")
            }
            const recovered = join(keyShamirRecover)
            const utf8Decoder = new TextDecoder();
            const decoded = utf8Decoder.decode(recovered);
            const decodedKey = JSON.parse(decoded)

            const importedKey = await subtle.importKey("jwk", decodedKey, Helper.ecdhKeyParams, true, ["deriveKey", "deriveBits"])
            
            keysRetrieved[clientDroppedID] = importedKey;
        }

        this.keysRetrieved = keysRetrieved
    }
 
    /**
     * Reconstruct the masks of the dropped clients
     */
    async reconstructDroppedClientsMask() {

        const buffer = new ArrayBuffer(4)
        const view = new DataView(buffer)
        view.setInt32(0, 0)

        for (const clientDroppedID in this.keysRetrieved) {

            const privateKeyOfDroppedUser = this.keysRetrieved[clientDroppedID]

            for (const clientIteratedID in this.clientListU2) {

                if (this.clientIDsU3.includes(clientIteratedID)) {
                    const clientAlive = this.clientListU2[clientIteratedID];
                    const seedBuffer = await Helper.deriveSharedNumber(privateKeyOfDroppedUser, clientAlive.seedPublicKey);
                    const seed = new DataView(seedBuffer, 0).getInt16(1);
                    const PRNG = Helper.getPRNGFromSeed(seed)
                    const mask = PRNG(2 ** 32)

                    if (clientAlive.id < clientDroppedID) {
                        view.setInt32(0, view.getInt32(0) + mask);
                    }
                    else {
                        view.setInt32(0, view.getInt32(0) - mask);
                    }

                }
            }
        }

        view.setInt32(0, view.getInt32(0) + this.agg)
        this.agg = Number.parseInt(view.getInt32(0))
    }
 
    /**
     * Reconstruct the seed of the remaining clients at U3
     */
    reconstructAliveClientsSeed() {

        let seedRecovered = {}

        for (let i = 0; i < this.clientIDsU3.length; ++i) {

            const clientAliveReconstructedID = this.clientIDsU3[i]
            let seedShamirRecover = {}

            for (const clientAliveReconstructionID in this.seedStocker) {
                seedShamirRecover[this.seedStocker[clientAliveReconstructionID][clientAliveReconstructedID]['index']] = this.seedStocker[clientAliveReconstructionID][clientAliveReconstructedID]['seedSplit'].split(",")
            }

            const recovered = join(seedShamirRecover)
            const utf8Decoder = new TextDecoder();
            const decoded = utf8Decoder.decode(recovered);

            seedRecovered[clientAliveReconstructedID] = decoded;
        }
        this.seedRecovered = seedRecovered;
    }
 
    /**
     * Remove the remaining clients mask from the seed
     */
    reconstructAliveClientsMask() {
        const buffer = new ArrayBuffer(4)
        const view = new DataView(buffer)

        for (const clientReconstructed in this.seedRecovered) {
            const seed = parseInt(this.seedRecovered[clientReconstructed])
            const valueMask = gen.create(seed)(2 ** 32)
            view.setInt32(0, valueMask + view.getInt32(0))
        }

        view.setInt32(0, this.agg - view.getInt32(0))
        this.agg = Number.parseInt(view.getInt32(0))
     }
     


    /**
     * In the round 3, the server collect the shamir t out of n shares.
     * Depending if the client has dropped or not, it generates the seed or the private key
     * After removing the mask the server computes the mean
     * @returns Gradient mean
     */
    async round3() {
        this.computeU5()
        this.collectResponses()
        await this.reconstructDroppedClientsKeys()
        await this.reconstructDroppedClientsMask()
        this.reconstructAliveClientsSeed()
        this.reconstructAliveClientsMask()
        return (this.agg / 10**4) / this.clientIDsU3.length
    }
 
    /**
     * Compute the aggregation result in a non secure way
     * @returns Aggregation mean
     */
    aggregateWithoutSecrecy() {
        let sum = 0;
        let count = 0;
        for (const clientIteratedID in this.clientList) {
            if (this.clientIDsU3.includes(clientIteratedID)) {
                sum += this.clientList[clientIteratedID].client.secretValue;
                count += 1;
            }
        }
        const mean = sum / count
        return mean
    }
}
 
/**
 * Data Storing class representing the clients in a server
 */
class ClientForServer {
    constructor(client, id, seedPublicKey, encryptionPublicKey) {
        this.client = client;
        this.id = id;
        this.seedPublicKey = seedPublicKey;
        this.encryptionPublicKey = encryptionPublicKey;
        this.isUp = true;
    }
}

module.exports = Server;