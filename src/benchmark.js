/**
 * This file enables the benchmarking of our protocol implementation
 */

/**
 * Imports
 */
const { randomUUID } = require('crypto').webcrypto;
const gen = require('random-seed');
const Server = require("./server.js")
const Client = require("./client.js")
const fs = require('fs')


/**
 * This functions runs the protocol multiple times and stores the computation 
 * time of one client and of the server at each round
 * @param {Number} nbClient  Number of clients simulated
 * @param {Number} nbIterPerBenchmark Number of iterations simulated
 * @returns The computation time at each round for each iteration
 */
async function benchmarkWithoutDropouts(nbClient, nbIterPerBenchmark) {
    console.log(`Benchmark without dropouts for ${nbClient} clients, and ${nbIterPerBenchmark} iteration`)

    let benchmark = {
        'clientRound0' : [],
        'serverRound0' : [],
        'clientRound1' : [],
        'serverRound1' : [],
        'clientRound2' : [],
        'serverRound2' : [],
        'clientRound3' : [],
        'serverRound3' : [],
    }

    for (let benchmarkRound = 0; benchmarkRound < nbIterPerBenchmark; ++benchmarkRound) {
        
        console.log(`Iteration number ${benchmarkRound}`)

        /* Clients and Server generation */

        let clientsArray = []
        const maxSecretValue = Math.floor(16384/nbClient)


        for (let i = 0; i < nbClient; ++i) {
            clientsArray.push(new Client(randomUUID(), gen.create().floatBetween(-maxSecretValue, maxSecretValue -1), nbClient, nbClient))
        }
        const server = new Server(clientsArray, nbClient, 2);
        

        /* Round 0v*/

        const startClient0 = new Date().getTime()
        await clientsArray[0].round0()
        const endClient0 = new Date().getTime()
        benchmark['clientRound0'].push(endClient0 - startClient0)

        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round0();
        }

        const startServer0 = new Date().getTime()
        await server.round0();
        const endServer0 = new Date().getTime()
        benchmark['serverRound0'].push(endServer0 - startServer0)


        /* Round 1 */

        const startClient1 = new Date().getTime()
        await clientsArray[0].round1()
        const endClient1 = new Date().getTime()
        benchmark['clientRound1'].push(endClient1 - startClient1)
        
        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round1();
        }

        const startServer1 = new Date().getTime()
        await server.round1();
        const endServer1 = new Date().getTime()
        benchmark['serverRound1'].push(endServer1 - startServer1)


        /* Round 2 */

        const startClient2 = new Date().getTime()
        clientsArray[0].round2()
        const endClient2 = new Date().getTime()
        benchmark['clientRound2'].push(endClient2 - startClient2)
        
        for (let i = 1; i < nbClient; ++i) {
            clientsArray[i].round2();
        }

        const startServer2 = new Date().getTime()
        server.round2();
        const endServer2 = new Date().getTime()
        benchmark['serverRound2'].push(endServer2 - startServer2)


        /* Round 3 */

        const startClient3 = new Date().getTime()
        await clientsArray[0].round3()
        const endClient3 = new Date().getTime()
        benchmark['clientRound3'].push(endClient3 - startClient3)
        
        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round3();
        }

        const startServer4 = new Date().getTime()
        const endServer4 = new Date().getTime()
        benchmark['serverRound3'].push(endServer4 - startServer4)
    }

    return benchmark
}

/**
 * The function simulates multiple benchmarks without dropout for multiple numbers of clients.
 * These numbers of clients are obtained using a start/end/step logic 
 * @param {Number} start 
 * @param {Number} end 
 * @param {Number} step 
 * @param {Number} nbIterPerBenchmark 
 * @param {Number} index index added to the saved json file name
 * @param {Boolean} writeToFile Indicates if the result should be saved as a json file
 */
async function benchmarksWithoutDropouts(start, end, step, nbIterPerBenchmark, index, writeToFile=false) {

    console.log(`Benchmark without dropouts starting at ${start} clients, finishing at ${end} clients with a step of ${step} and ${nbIterPerBenchmark} iterations per benchmark `)
    
    let benchmarks = {}

    for (let i = start; i < end; i+= step){
        const benchmarkRound =await benchmarkWithoutDropouts(i, nbIterPerBenchmark)
        benchmarks[i] = benchmarkRound
    }

    const jsonBenchmark = JSON.stringify(benchmarks)

    if (writeToFile) {
        fs.writeFile(`benchmark/benchmark_results/no_dropouts_${index}_${nbIterPerBenchmark}.json`, jsonBenchmark, function(err) {
            if (err) {
                console.log(err);
            }
        });
    }
}



/**
 * This functions runs the protocol with dropouts multiple times and stores the computation 
 * time of one client and of the server at each round
 * Clients drop at the end of round 1 as it is the "worst case" dropout
 * @param {Number} nbClient  Number of clients simulated
 * @param {Number} dropouts Number of users dropping out during the protocol
 * @param {Number} nbIterPerBenchmark Number of iterations simulated
 * @returns The computation time at each round for each iteration
 */
async function benchmarkWithDropouts(nbClient, dropouts, nbIterPerBenchmark) {

    console.log(`Benchmark with dropouts for ${nbClient} clients, ${dropouts} dropouts, and ${nbIterPerBenchmark} iterations`)
    
    let benchmark = {
        'clientRound0' : [],
        'serverRound0' : [],
        'clientRound1' : [],
        'serverRound1' : [],
        'clientRound2' : [],
        'serverRound2' : [],
        'clientRound3' : [],
        'serverRound3' : [],
    }

    for  (let benchmarkRound = 0; benchmarkRound < nbIterPerBenchmark; ++benchmarkRound) {

        console.log(`Iteration number ${benchmarkRound}`)

        /* Generation of the dropped clients indexes */

        let dropoutArray = []
        const randomNumberGenerator = gen.create()

        let nbDropout = 0
        while (nbDropout < dropouts) {
            const randomNumber = randomNumberGenerator(nbClient)
            if ((!dropoutArray.includes(randomNumber)) && (randomNumber != 0)) {
                dropoutArray.push(randomNumber)
                ++nbDropout
            }
        }

        /* Server and Client generation */

        let clientsArray = []
        const maxSecretValue = Math.floor(131072/nbClient)

        for (let i = 0; i < nbClient; ++i) {
            clientsArray.push(new Client(randomUUID(), gen.create().floatBetween(-maxSecretValue, maxSecretValue -1), nbClient, 2))
        }
        const server = new Server(clientsArray, nbClient, 2);


        /* Round 0 */

        const startClient0 = new Date().getTime()
        await clientsArray[0].round0()
        const endClient0 = new Date().getTime()
        benchmark['clientRound0'].push(endClient0 - startClient0)

        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round0();
        }

        const startServer0 = new Date().getTime()
        await server.round0();
        const endServer0 = new Date().getTime()
        benchmark['serverRound0'].push(endServer0 - startServer0)
        

        /* Round 1 */

        const startClient1 = new Date().getTime()
        await clientsArray[0].round1()
        const endClient1 = new Date().getTime()
        benchmark['clientRound1'].push(endClient1 - startClient1)
        
        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round1();
        }
        
        const startServer1 = new Date().getTime()
        await server.round1();
        const endServer1 = new Date().getTime()
        benchmark['serverRound1'].push(endServer1 - startServer1)


        /* Dropping clients */

        for (let i = 0; i < dropoutArray.length; ++i) {
            clientsArray[dropoutArray[i]].putDown()
        }


        /* Round 2 */

        const startClient2 = new Date().getTime()
        clientsArray[0].round2()
        const endClient2 = new Date().getTime()
        benchmark['clientRound2'].push(endClient2 - startClient2)
        
        for (let i = 1; i < nbClient; ++i) {
            clientsArray[i].round2();
        }

        const startServer2 = new Date().getTime()
        server.round2();
        const endServer2 = new Date().getTime()
        benchmark['serverRound2'].push(endServer2 - startServer2)


        /* Round 3*/

        const startClient3 = new Date().getTime()
        await clientsArray[0].round3()
        const endClient3 = new Date().getTime()
        benchmark['clientRound3'].push(endClient3 - startClient3)
        
        for (let i = 1; i < nbClient; ++i) {
            await clientsArray[i].round3();
        }

        const startServer4 = new Date().getTime()
        const endServer4 = new Date().getTime()
        benchmark['serverRound3'].push(endServer4 - startServer4)
    }

    return benchmark
}


/**
 * The function simulates multiple benchmarks with dropout for multiple numbers of clients
 * and multiple dropout rates
 * The numbers of clients and the dropout rates are obtained using a start/end/step logic 
 * @param {Number} startClient 
 * @param {Number} endClient 
 * @param {Number} stepClient 
 * @param {Number} startDropout 
 * @param {Number} endDropout 
 * @param {Number} stepDropout 
 * @param {Number} nbIterPerBenchmark
 * @param {Number} index index added to the saved json file name
 * @param {Boolean} writeToFile Indicates if the result should be saved as a json file
 */

async function benchmarksWithDropouts(startClient, endClient, stepClient, startDropout, endDropout, stepDropout, nbIterPerBenchmark, index, writeToFile=false) {
    
    console.log(`Benchmark with dropouts starting at ${startClient} clients, finishing at ${endClient} clients with a step of ${stepClient} and ${nbIterPerBenchmark} iterations per benchmark `)
    console.log(`The dropout rates begins at ${startDropout}, finishes at ${endDropout} and has a step of ${stepDropout}`)

    for (let j = startDropout; j < endDropout; j += stepDropout) {

        let benchmark = {}

        for (let i = startClient; i < endClient; i+= stepClient) {
            const benchmarkRound = await benchmarkWithDropouts(i, Math.floor(i*j), nbIterPerBenchmark)
            benchmark[i] = benchmarkRound
        }

        const jsonBenchmark = JSON.stringify(benchmark)
        if (writeToFile) {
            fs.writeFile(`benchmark/benchmark_results/dropouts_${index}_${j}_${nbIterPerBenchmark}.json`, jsonBenchmark, function(err) {
                if (err) {
                    console.log(err);
                }
            });
        }

    }
}


/**
 * The function perform the different benchmarks shown in the report
 */
async function benchmarks() {
    await benchmarksWithoutDropouts(5, 16, 5, 2, 42, true)
    await benchmarksWithDropouts(5, 16, 5, 0.2, 0.41, 0.2, 2, 42, true)
}

benchmarks()
