# semester-project-privacy-vincent

Fall 2021 EPFL Semester Project of Yuan Vincent done in the Machine Learning and Optimization Laboratory.

This project implements the [Secure Aggregation Protocol](https://dl.acm.org/doi/10.1145/3133956.3133982) from Bonawitz et al. in Node.js.

## Launching a simulation

Node.js v17.3.0 is required to run the program.

Importing the modules: 

`npm install`

Launching the simple simulation:

`npm run src/run.js`

The simple simulation runs 4 clients with a threshold of 2. It drops one user during the process.

The user can personalize its run of the simulation by calling the function `runPersonalized` in `src/run.js` and changing the arguments to simulate any given number of clients, threshold, and dropouts.

## Project Structure

The project structure is composed as such: 

```bash
├── benchmark
│   ├── benchmark.js
│   ├── benchmark_plot.ipynb
│   ├── benchmark_results
│   ├── plots
├── node_modules
├── package.json
├── package-lock.json
├── project_report.pdf
├── README.md
└── src
    ├── client.js
    ├── helper.js
    ├── run.js
    └── server.js
```

The folder `src/` contains the protocol implementation. The implementation is performed in the three files `src/helper.js`, `src/client.js`, and `src/server.js`. The implementation can be launched from `src/run.js`.

The folder `benchmark/` contains all the benchmarking-related files. The file `benchmark/benchmark.js` runs the benchmarking detailed in the report. The file `benchmark/benchmark_plot.ipynb` creates the plots. The benchmark results can be found in the folder `benchmark/benchmark_results/` and the plots can be found in the folder `benchmark/plots`.

## Implementation choices

The most confusing implementation choices, such as the use of `DataView` to perform some computations, is explained in the project report section IV-B)

## Acknowledgment

Special thanks to Ignacio Saleman, Lie He, Mary-Anne Hartley and Martin Jaggi for their help during the project.