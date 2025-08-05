# Votegral w/ TRIP Registration

This repository contains the reference implementation and simulation framework for 
Votegral, an end-to-end verifiable, coercion-resistant, and linear-time voting 
system. TRIP is a verifiable, coercion-resistant in-person registration system
that Votegral uses to issue credentials to eligible voters.


The simulation models the entire lifecycle of a voter's interaction, 
from in-person registration using the TRIP protocol to casting a 
ballot online. 
The framework also includes a complete, simulated distributed tallying process. 
This artifact is designed for performance evaluation, 
benchmarking, and reproducibility.

## Table of Contents

<!-- TOC -->
* [Votegral w/ TRIP Registration](#votegral-w-trip-registration)
  * [Table of Contents](#table-of-contents)
  * [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation and Basic Run](#installation-and-basic-run)
      * [Docker](#docker)
      * [Local](#local)
  * [Project Structure](#project-structure)
  * [Configuration](#configuration)
    * [Command Line Arguments](#command-line-arguments)
    * [Hardware Modes](#hardware-modes)
    * [Shuffle Modes](#shuffle-modes)
    * [Simulation Output](#simulation-output)
      * [Metrics](#metrics)
  * [Papers](#papers)
  * [Acknowledgments](#acknowledgments)
<!-- TOC -->

## Getting Started

### Prerequisites

-   **Go**: Version [1.23.11](https://go.dev/dl/#go1.23.11) or later. You can download it from the [official Go website](https://go.dev/dl/#go1.23.11). Follow the [official installation instructions](https://go.dev/doc/install).
-   **Git**: Required to clone the repository.

### Installation and Basic Run

Votegral can be built and run inside a docker container or locally.

#### Docker

```bash
docker build --no-cache -t votegral .
docker run votegral
```

#### Local

Setup tested on Ubuntu 24.04 (as of July 2025)

1.  **Clone the Repository:**
    ```bash
    sudo apt-get update && sudo apt-get install git
    git clone https://github.com/dedis/votegral.git
    cd votegral
    ```

2.  **Build and Run the Simulation:**  
    ```bash
    # Install Go (only if needed)
    wget https://go.dev/dl/go1.23.11.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.23.11.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    
    # Build Votegral
    cd cmd/simulation
    go build .
    ./simulation --runs=1 --voters=100 --shuffle=BayerGroth --print-metrics
    
    # To see all available options
    ./simulation --help
    ```
    
3.  **Run Votegral w/ BayerGroth Shuffle**  (x86 and x64 architectures only)  
    BayerGroth shuffle implementation is available in C++ thanks to [Anders Dalskov's repo](https://github.com/anderspkd/groth-shuffle).
    
    ```bash
    sudo apt-get update && sudo apt-get install build-essential cmake catch2 libgmp-dev python3
    cd prerequisites/anderspkd_groth-shuffle
    
    # Install Catch2 v2
    git clone https://github.com/catchorg/Catch2.git
    cd Catch2 && git checkout v2.x && cmake -B build -S .
    sudo cmake --build build --target install
    
    # Build BayerGroth Shuffle
    cd ../
    cmake . -B build && cd build && make && make test
    ./tests.x # All Tests should pass
    
    # Copy custom BayerGroth Shuffle App
    cp ./shuffle_app ../../../cmd/simulation/
    
    # Run Votegral w/ BayerGroth Shuffle
    cd ../../../cmd/simulation/
    ./simulation --runs=1 --voters=100 --shuffle=BayerGroth --print-metrics
    ```

---

## Project Structure

The core logic is in the `pkg` directory, while the executable application is in the `cmd` directory.

-   **`cmd/simulation/`**: The main application entry point. It handles configuration parsing, sets up the simulation environment, executes the run, and writes the results.
-   **`pkg/`**: The core package that defines the Votegral system.
    -   **`actors/`**: Introduces participants, such as the `ElectionAuthority`, `Voter`, and `Kiosk`.
    -   **`concurrency/`**: Provides methods for parallelizable tasks.
    -   **`config/`**: Parses configuration from command-line flags.
    -   **`context/`**: Provides a shared context for operations.
    -   **`crypto/`**: Provides the necessary cryptographic primitives.
    -   **`hardware/`**: Provides an abstraction layer for interacting with physical or simulated hardware.
    -   **`io/`**: Handles input/output operations for different readers and writers (e.g., in-memory, disk-based, and peripherals).
    -   **`ledger/`**: Implements a shared data storage among the participants.
    -   **`log/`**: Provides a custom logging implementation.
    -   **`metrics/`**: Record operations and aggregate performance metrics (e.g., WallClock, CPU time).
    -   **`protocol/`**: Orchestrates the high-level cryptographic protocols for registration, activation, and voting.
    -   **`result/`**: Manages the formatting and writing of simulation results into CSV files.
    -   **`serialization/`**: Provides utilities for converting data structures to and from serializable formats.
-   **`output/`**: The default directory for all generated artifacts.

## Configuration

The simulation's behavior is controlled via command-line flags.

### Command Line Arguments

| Flag            | Type   | Default          | Description                                                                   |
|-----------------|--------|------------------|-------------------------------------------------------------------------------|
| --runs          | uint64 | 2                | Number of times to run the simulation.                                        |
| --cores         | uint64 | 1                | Number of CPU cores (0 for All) - `1` for sequential run (w/ add. metrics)    |
| --voters        | uint64 | 100              | Number of voters to simulate (registration + voting).                         |
| --fake-creds    | uint64 | 1                | Number of fake credentials for each voter.                                    |
| --ea-members    | uint64 | 4                | Number of Election Authority Members.                                         |
| --system        | string | Mac              | System tag (`Mac`, `Kiosk`, `Pi`, `Xeon`) for logging and system-level logic. |
| --hw            | string | Core             | [Hardware modes](#hardware-modes) (`Core`, `Disk`, `Peripherals`).            |
| --shuffle       | string | Neff             | Type of Verifiable Shuffle (`Neff`, `BayerGroth`).                            |
| --printer       | string | TM               | Name of the printer in CUPS if Peripheral is enabled.                         |
| --cups-wait     | int    | 100              | Wait time (ms) for CUPS daemon to start for measurement.                      |
| --pics          | string | "output/pics"    | Path for storing pictures of physical materials.                              |
| --results       | string | "output/results" | Path for storing simulation results.                                          |
| --temp          | string | "output/tmp/"    | Path for storing temporary files.                                             |
| --print-metrics | string | false            | Whether to print detailed metrics tree at the end.                            |
| --max-depth     | int    | 2                | Maximum depth of the metrics tree to print                                    |
| --max-children  | int    | 10               | Maximum number of children to print for each node.                            |
| --seed          | string | votegral         | Seed for deterministic random output.                                         |
| --log-level     | string | info             | Set log level (`trace`, `debug`, `info`, `error`).                            |


### Hardware Modes

The simulation can run in different hardware modes, configured via the `-hw` flag:

-   **`Core`**: An in-memory mock that performs no external I/O. This is the fastest mode and is ideal for benchmarking the core cryptographic protocol.
-   **`Disk`**: Simulates I/O by writing and reading QR code files to and from the disk. This measures the overhead of file system operations.
-   **`Peripheral`**: Enables interaction with physical hardware like printers and cameras, providing the most realistic performance data.

### Shuffle Modes

The simulation supports two verifiable shuffle implementations, configured via the `--shuffle` flag:

- **Neff**: Andrew Neff's verifiable shuffle scheme thanks to `dedis/kyber`
- **Bayer and Groth**: Bayer and Groth's verifiable shuffle scheme thanks to `anderspkd/groth-shuffle`

### Simulation Output

-   **Performance Data**: The simulation generates detailed performance and resource usage data in CSV format, saved to the directory specified by the `-results` flag (default: `output/results/`). Both raw, per-operation data and aggregated statistical results are provided.
-   **Physical Artifacts**: If using `Disk` or `Peripheral` modes, generated QR codes are saved as PDF/image files in the `-pics` directory (default: `output/pics/`).

#### Metrics

```bash
./simulation --hw Disk --voters 2 --fake-creds 1 --runs 1  --print-metrics --max-depth -1 --max-children -1
```
```
--- Measurement Tree (Depth <= -1) ---
└── Simulation (Logic) - 330.012ms
    ├── Setup (Logic) - 32.408ms
    │   ├── CreateAnEnvelope (Logic) - 8.394ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 8.345ms
    │   ├── CreateAnEnvelope_1 (Logic) - 7.532ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 7.491ms
    │   ├── CreateAnEnvelope_2 (Logic) - 8.974ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 8.928ms
    │   └── CreateAnEnvelope_3 (Logic) - 7.477ms
    │       └── SaveFile_Envelope (DiskWrite) - 7.414ms
    ├── Registration (Logic) - 245.728ms
    │   ├── RegisterAVoter (Logic) - 126.346ms
    │   │   ├── CheckInAVoter_Official (Logic) - 1.425ms
    │   │   │   └── SaveFile_CheckInBarcode (DiskWrite) - 1.415ms
    │   │   ├── CheckInAVoter_Kiosk (Logic) - 3.442ms
    │   │   │   └── ReadFile_CheckInBarcode (DiskRead) - 3.437ms
    │   │   ├── CreateARealCredential (Logic) - 30.293ms
    │   │   │   ├── SaveFile_Commit (DiskWrite) - 7.893ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 8.353ms
    │   │   │   ├── SaveFile_Checkout (DiskWrite) - 7.473ms
    │   │   │   └── SaveFile_Response (DiskWrite) - 6.283ms
    │   │   ├── CreateAFakeCredential (Logic) - 29.854ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 8.386ms
    │   │   │   ├── SaveFile_Commit (DiskWrite) - 7.469ms
    │   │   │   ├── SaveFile_Checkout (DiskWrite) - 7.485ms
    │   │   │   └── SaveFile_Response (DiskWrite) - 6.175ms
    │   │   ├── CheckoutAVoter (Logic) - 8.899ms
    │   │   │   └── ReadFile_Checkout (DiskRead) - 8.802ms
    │   │   ├── ActivateACredential (Logic) - 26.549ms
    │   │   │   ├── ReadFile_Commit (DiskRead) - 9.202ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 8.683ms
    │   │   │   └── ReadFile_Response (DiskRead) - 8.289ms
    │   │   ├── ActivateACredential_1 (Logic) - 25.852ms
    │   │   │   ├── ReadFile_Commit (DiskRead) - 9.005ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 8.286ms
    │   │   │   └── ReadFile_Response (DiskRead) - 8.218ms
    │   │   └── EAPostingCreds (Logic) - 1µs
    │   └── RegisterAVoter_1 (Logic) - 119.378ms
    │       ├── CheckInAVoter_Official (Logic) - 1.493ms
    │       │   └── SaveFile_CheckInBarcode (DiskWrite) - 1.488ms
    │       ├── CheckInAVoter_Kiosk (Logic) - 1.982ms
    │       │   └── ReadFile_CheckInBarcode (DiskRead) - 1.972ms
    │       ├── CreateARealCredential (Logic) - 29.373ms
    │       │   ├── SaveFile_Commit (DiskWrite) - 7.523ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 8.192ms
    │       │   ├── SaveFile_Checkout (DiskWrite) - 7.076ms
    │       │   └── SaveFile_Response (DiskWrite) - 6.133ms
    │       ├── CreateAFakeCredential (Logic) - 28.755ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 8.074ms
    │       │   ├── SaveFile_Commit (DiskWrite) - 7.436ms
    │       │   ├── SaveFile_Checkout (DiskWrite) - 7.082ms
    │       │   └── SaveFile_Response (DiskWrite) - 5.875ms
    │       ├── CheckoutAVoter (Logic) - 8.665ms
    │       │   └── ReadFile_Checkout (DiskRead) - 8.586ms
    │       ├── ActivateACredential (Logic) - 24.691ms
    │       │   ├── ReadFile_Commit (DiskRead) - 8.427ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 8.166ms
    │       │   └── ReadFile_Response (DiskRead) - 7.775ms
    │       ├── ActivateACredential_1 (Logic) - 24.396ms
    │       │   ├── ReadFile_Commit (DiskRead) - 8.284ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 7.933ms
    │       │   └── ReadFile_Response (DiskRead) - 7.845ms
    │       └── EAPostingCreds (Logic) - 0s
    ├── Voting (Logic) - 1.974ms
    │   ├── CastAVote (Logic) - 497µs
    │   ├── CastAVote_1 (Logic) - 508µs
    │   ├── CastAVote_2 (Logic) - 479µs
    │   └── CastAVote_3 (Logic) - 484µs
    └── Tally (Logic) - 49.841ms
        ├── Tally_0_VerifyLedgerContents (Logic) - 2.081ms
        ├── Tally_1_ShuffleRegistrationRecords (Logic) - 6.225ms
        │   ├── Shuffle (Logic) - 621µs
        │   ├── ShuffleVerify (Logic) - 1.162ms
        │   ├── Shuffle_1 (Logic) - 582µs
        │   ├── ShuffleVerify_1 (Logic) - 905µs
        │   ├── Shuffle_2 (Logic) - 567µs
        │   ├── ShuffleVerify_2 (Logic) - 901µs
        │   ├── Shuffle_3 (Logic) - 572µs
        │   └── ShuffleVerify_3 (Logic) - 901µs
        ├── Tally_2_DeterministicTagsOnShuffledRegistrationRecords (Logic) - 6.033ms
        │   ├── GenerateDeterministicTags (Logic) - 3.038ms
        │   └── VerifyDeterministicTags (Logic) - 2.992ms
        ├── Tally_3_ShuffleVotingRecords (Logic) - 20.778ms
        │   ├── Shuffle (Logic) - 2.355ms
        │   ├── ShuffleVerify (Logic) - 2.745ms
        │   ├── Shuffle_1 (Logic) - 2.329ms
        │   ├── ShuffleVerify_1 (Logic) - 2.927ms
        │   ├── Shuffle_2 (Logic) - 2.396ms
        │   ├── ShuffleVerify_2 (Logic) - 2.803ms
        │   ├── Shuffle_3 (Logic) - 2.444ms
        │   └── ShuffleVerify_3 (Logic) - 2.763ms
        ├── Tally_4_DeterministicTagsOnShuffledVotingRecords (Logic) - 12.147ms
        │   ├── GenerateDeterministicTags (Logic) - 5.974ms
        │   └── VerifyDeterministicTags (Logic) - 6.166ms
        ├── Tally_5_FilterRealVotes (Logic) - 6µs
        ├── Tally_6_DecryptVotes (Logic) - 2.439ms
        │   ├── MultiKeyDecryptWithProof (Logic) - 637µs
        │   ├── VerifyDecryptionProofs (Logic) - 575µs
        │   ├── MultiKeyDecryptWithProof_1 (Logic) - 648µs
        │   └── VerifyDecryptionProofs_1 (Logic) - 570µs
        └── Tally_7_TallyResults (Logic) - 1µs
======================================================
       Median Phase Times (Per Simulation Run)        
------------------------------------------------------
 Config: 1 runs, 2 voters, 1 fakes
         Disk hw, Neff shuffle
======================================================
 Simulation (Total)...................... 330.011ms
   ├─ Setup............................... 32.407ms
   ├─ Registration....................... 245.727ms
   ├─ Voting............................... 1.974ms
   └─ Tally................................ 49.84ms
======================================================
```

---

## Papers

The following papers are related to Votegral and TRIP:

-   `L. Merino et al., "E-Vote Your Conscience: Perceptions of Coercion and Vote Buying, and the Usability of Fake Credentials in Online Voting," in 2024 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2024, pp. 3478-3496, doi: 10.1109/SP54263.2024.00252.`
-   `L. Merino et al., TRIP: Coercion-Resistant In-Person Registration for E-Voting with Verifiability and Usability in Votegral. To appear in the 31st ACM Symposium on Operating Systems Principles (SOSP 2025), Seoul, Republic of Korea, 2025`

## Acknowledgments

The use of AI (ChatGPT and Gemini) to ensure robust code quality and documentation for archival purposes.