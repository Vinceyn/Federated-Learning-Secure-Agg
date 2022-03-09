/**
 * This file enables the running of the Secure Aggregation Protocol
 */

/**
 * Imports
 */
const { randomUUID } = require('crypto').webcrypto;
const gen = require('random-seed');
const Server = require("./server.js")
const Client = require("./client.js")

/**
 * Runs the protocol for n = 4 clients with a threshold of two with one dropout at the end of round 1
 */
 async function runSimple() {

    console.log("Run a simple instance of the protocol without dropouts")

    /* Clients and Server generation */

    const client0 = new Client(randomUUID(), 131070.213213, 4, 2);
    const client1 = new Client(randomUUID(), 3.14159265, 4, 2);
    const client2 = new Client(randomUUID(), -42, 4, 2);
    const client3 = new Client(randomUUID(), 6, 4, 2);

    const server = new Server([client0, client1, client2, client3], 4, 2);


    console.log("Round 0\n")

    await client0.round0();
    await client1.round0();
    await client2.round0();
    await client3.round0();

    await server.round0();

    
    console.log("Round 1\n")

    await client0.round1();
    await client1.round1();
    await client2.round1();
    await client3.round1();

    await server.round1();

    client0.putDown()


    console.log("Round 2\n")

    client0.round2();
    client1.round2();
    client2.round2();
    client3.round2();

    server.round2();

    
    console.log("Round 3\n")

    await client0.round3();
    await client1.round3();
    await client2.round3();
    await client3.round3();

    let masked = await server.round3()


    console.log(masked)
    console.log(server.aggregateWithoutSecrecy());
}
 

/**
 * Run the protocol with a given threshold and a given number of clients.
 * Simulate client dropouts by taking as parameters the number of drop out at 6 possible spots
 * @param {Number} nbClient 
 * @param {Number} threshold 
 * @param {Number} dropout11 
 * @param {Number} dropout12 
 * @param {Number} dropout21 
 * @param {Number} dropout22 
 * @param {Number} dropout31 
 * @param {Number} dropout32 
 */
async function runPersonalized(nbClient, threshold, dropout11=0, dropout12=0, dropout21=0, dropout22=0, dropout31=0, dropout32=0) {
    console.log(`Test 2 with ${nbClient} number of clients, a threshold of ${threshold} clients
${dropout11} dropouts before the client round 1, ${dropout12} dropouts before the server round 1
${dropout21} dropouts before the client round 2, ${dropout22} dropouts before the server round 2
${dropout31} dropouts before the client round 4, ${dropout32} dropouts before the server round 4`)


    /* Prepare dropouts by generating the indexes of the clients that will drop out during the protocol */
    const dropoutLength = [dropout11, dropout12, dropout21, dropout22, dropout31, dropout32]
    let dropoutArray = []
    let dropoutArrayIndex = []

    for (let i = 0; i < dropoutLength.length; ++i) {

        const nbDropout = dropoutLength[i];
        dropoutArrayIndex[i] = []

        let j = 0

        while (j < nbDropout) {

            const randomNumberGenerator = gen.create()
            const randomNumber = randomNumberGenerator(nbClient)

            if (!dropoutArray.includes(randomNumber)) {
                dropoutArray.push(randomNumber)
                dropoutArrayIndex[i].push(randomNumber)
                ++j
            }
        }
    }

    /* Clients and Server generation */

    let clientsArray = []
    const maxSecretValue = Math.floor(131072/nbClient)

    for (let i = 0; i < nbClient; ++i) {
        clientsArray.push(new Client(randomUUID(), gen.create().floatBetween(-maxSecretValue, maxSecretValue -1), nbClient, threshold))
    }

    const server = new Server(clientsArray, nbClient, threshold);
    
    /* Round 0*/ 

    console.log("Round 0\n")

    for (let i = 0; i < nbClient; ++i) {
        await clientsArray[i].round0();
    }

    await server.round0();

    /* Round 1 */

    console.log("Round 1\n\n")

    for (let i = 0; i < dropoutArrayIndex[0].length; ++i) {
        clientsArray[dropoutArrayIndex[0][i]].putDown()
    }

    for (let i = 0; i < nbClient; ++i) {
        await clientsArray[i].round1();
    }
    
    for (let i = 0; i < dropoutArrayIndex[1].length; ++i) {
        clientsArray[dropoutArrayIndex[1][i]].putDown()
    }

    await server.round1();


    /* Round 2 */

    console.log("Round 2\n")

    for (let i = 0; i < dropoutArrayIndex[2].length; ++i) {
        clientsArray[dropoutArrayIndex[2][i]].putDown()
    }

    for (let i = 0; i < nbClient; ++i) {
        clientsArray[i].round2();
    }

    for (let i = 0; i < dropoutArrayIndex[3].length; ++i) {
        clientsArray[dropoutArrayIndex[3][i]].putDown()
    }

    server.round2()


    /* Round 3*/

    console.log("Round 3\n\n")

    for (let i = 0; i < dropoutArrayIndex[4].length; ++i) {
        clientsArray[dropoutArrayIndex[4][i]].putDown()
    }

    for (let i = 0; i < nbClient; ++i) {
        await clientsArray[i].round3();
    }

    for (let i = 0; i < dropoutArrayIndex[5].length; ++i) {
        clientsArray[dropoutArrayIndex[5][i]].putDown()
    }

    let masked = await server.round3()
    

    console.log(masked)
    console.log(server.aggregateWithoutSecrecy());
}
 
runSimple();
// runPersonalized(10, 2, 1, 2, 1, 1, 1, 0);