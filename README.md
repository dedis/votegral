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

---<!-- TOC -->
* [Votegral w/ TRIP Registration](#votegral-w-trip-registration)
  * [Table of Contents](#table-of-contents)
  * [Getting Started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Installation and Basic Run](#installation-and-basic-run)
  * [Project Structure](#project-structure)
  * [Configuration](#configuration)
    * [Command Line Arguments](#command-line-arguments)
    * [Hardware Modes](#hardware-modes)
    * [Simulation Output](#simulation-output)
      * [Detailed Metrics](#detailed-metrics)
  * [Reproducibility](#reproducibility)
    * [Testbed Environment](#testbed-environment)
    * [Peripheral Requirements](#peripheral-requirements)
    * [Command-Line Arguments](#command-line-arguments-1)
    * [Results](#results)
  * [Papers](#papers)
  * [Acknowledgments](#acknowledgments)
<!-- TOC -->

## Getting Started

Follow these steps to get the simulation running on your local machine.

### Prerequisites

-   **Go**: Version [1.23.11](https://go.dev/dl/#go1.23.11) or later. You can download it from the [official Go website](https://go.dev/dl/#go1.23.11). Follow the [official installation instructions](https://go.dev/doc/install).
-   **Git**: Required to clone the repository.

### Installation and Basic Run

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-repo/votegral.git
    cd votegral
    ```

2.  **Build and Run the Simulation:**
    The `go build` command will automatically fetch all required dependencies. The following commands build the executable and run a default simulation with 100 voters in the fast, in-memory `Core` mode.

    ```bash
    cd cmd/simulation
    go build .
    ./simulation --voters=100 --hw=Core
    ```
    To see all available options, run `./simulation --help`.

---

## Project Structure

The core logic is in the `pkg` directory, while the executable application is in the `cmd` directory.

-   **`cmd/simulation/`**: The main application entry point. It handles configuration parsing, sets up the simulation environment, executes the run, and writes the results.
-   **`pkg/`**: The core package that defines the Votegral system.
    -   **`actors/`**: Introduces participants, such as the `ElectionAuthority`, `Voter`, and `Kiosk`.
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
| --voters        | uint64 | 100              | Number of voters to simulate (registration + voting).                         |
| --fake-creds    | uint64 | 1                | Number of fake credentials for each voter.                                    |
| --ea-members    | uint64 | 4                | Number of Election Authority Members.                                         |
| --system        | string | Mac              | System tag (`Mac`, `Kiosk`, `Pi`, `Xeon`) for logging and system-level logic. |
| --hw            | string | Core             | [Hardware modes](#hardware-configuration) (`Core`, `Disk`, `Peripherals`)     |
| --printer       | string | TM               | Name of the printer in CUPS if Peripheral is enabled.                         |
| --cups-wait     | int    | 100              | Wait time (ms) for CUPS daemon to start for measurement.                      |
| --pics          | string | "output/pics"    | Path for storing pictures of physical materials.                              |
| --results       | string | "output/results" | Path for storing simulation results.                                          |
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

### Simulation Output

-   **Performance Data**: The simulation generates detailed performance and resource usage data in CSV format, saved to the directory specified by the `-results` flag (default: `output/results/`). Both raw, per-operation data and aggregated statistical results are provided.
-   **Physical Artifacts**: If using `Disk` or `Peripheral` modes, generated QR codes are saved as PDF/image files in the `-pics` directory (default: `output/pics/`).

#### Detailed Metrics

```bash
go run ./cmd/simulation/ --hw Disk --voters 2 --fake-creds 1 --runs 1  --print-metrics --max-depth -1 --max-children -1
```
```
--- Measurement Tree (Depth <= -1) ---
└── Simulation (Logic) - 349.791ms
    ├── Setup (Logic) - 22.917ms
    │   ├── CreateAnEnvelope (Logic) - 6.751ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 6.579ms
    │   ├── CreateAnEnvelope_1 (Logic) - 5.692ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 5.574ms
    │   ├── CreateAnEnvelope_2 (Logic) - 5.326ms
    │   │   └── SaveFile_Envelope (DiskWrite) - 5.21ms
    │   └── CreateAnEnvelope_3 (Logic) - 5.133ms
    │       └── SaveFile_Envelope (DiskWrite) - 5.022ms
    ├── Registration (Logic) - 222.034ms
    │   ├── RegisterAVoter (Logic) - 113.941ms
    │   │   ├── CheckInAVoter_Official (Logic) - 1.589ms
    │   │   │   └── SaveFile_CheckInBarcode (DiskWrite) - 1.585ms
    │   │   ├── CheckInAVoter_Kiosk (Logic) - 3.747ms
    │   │   │   └── ReadFile_CheckInBarcode (DiskRead) - 3.74ms
    │   │   ├── CreateARealCredential (Logic) - 27.067ms
    │   │   │   ├── SaveFile_Commit (DiskWrite) - 7.106ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 7.448ms
    │   │   │   ├── SaveFile_Checkout (DiskWrite) - 5.791ms
    │   │   │   └── SaveFile_Response (DiskWrite) - 5.944ms
    │   │   ├── CreateAFakeCredential (Logic) - 25.331ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 6.782ms
    │   │   │   ├── SaveFile_Commit (DiskWrite) - 6.229ms
    │   │   │   ├── SaveFile_Checkout (DiskWrite) - 5.574ms
    │   │   │   └── SaveFile_Response (DiskWrite) - 5.625ms
    │   │   ├── CheckoutAVoter (Logic) - 8.21ms
    │   │   │   └── ReadFile_Checkout (DiskRead) - 7.907ms
    │   │   ├── ActivateACredential (Logic) - 24.144ms
    │   │   │   ├── ReadFile_Commit (DiskRead) - 8.125ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 6.953ms
    │   │   │   └── ReadFile_Response (DiskRead) - 8.089ms
    │   │   ├── ActivateACredential_1 (Logic) - 23.715ms
    │   │   │   ├── ReadFile_Commit (DiskRead) - 8.296ms
    │   │   │   ├── ReadFile_Envelope (DiskRead) - 6.658ms
    │   │   │   └── ReadFile_Response (DiskRead) - 7.824ms
    │   │   └── EAPostingCreds (Logic) - 1µs
    │   └── RegisterAVoter_1 (Logic) - 108.075ms
    │       ├── CheckInAVoter_Official (Logic) - 1.427ms
    │       │   └── SaveFile_CheckInBarcode (DiskWrite) - 1.419ms
    │       ├── CheckInAVoter_Kiosk (Logic) - 1.932ms
    │       │   └── ReadFile_CheckInBarcode (DiskRead) - 1.929ms
    │       ├── CreateARealCredential (Logic) - 24.379ms
    │       │   ├── SaveFile_Commit (DiskWrite) - 6.062ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 6.487ms
    │       │   ├── SaveFile_Checkout (DiskWrite) - 5.547ms
    │       │   └── SaveFile_Response (DiskWrite) - 5.426ms
    │       ├── CreateAFakeCredential (Logic) - 24.862ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 6.649ms
    │       │   ├── SaveFile_Commit (DiskWrite) - 6.175ms
    │       │   ├── SaveFile_Checkout (DiskWrite) - 5.66ms
    │       │   └── SaveFile_Response (DiskWrite) - 5.481ms
    │       ├── CheckoutAVoter (Logic) - 8.19ms
    │       │   └── ReadFile_Checkout (DiskRead) - 7.893ms
    │       ├── ActivateACredential (Logic) - 23.567ms
    │       │   ├── ReadFile_Commit (DiskRead) - 8.137ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 6.712ms
    │       │   └── ReadFile_Response (DiskRead) - 7.779ms
    │       ├── ActivateACredential_1 (Logic) - 23.626ms
    │       │   ├── ReadFile_Commit (DiskRead) - 8.155ms
    │       │   ├── ReadFile_Envelope (DiskRead) - 6.781ms
    │       │   └── ReadFile_Response (DiskRead) - 7.754ms
    │       └── EAPostingCreds (Logic) - 0s
    ├── Voting (Logic) - 4.669ms
    │   ├── CastAVote (Logic) - 1.195ms
    │   ├── CastAVote_1 (Logic) - 1.174ms
    │   ├── CastAVote_2 (Logic) - 1.208ms
    │   └── CastAVote_3 (Logic) - 1.072ms
    └── Tally (Logic) - 100.105ms
        ├── Tally_0_VerifyLedgerContents (Logic) - 5.396ms
        │   ├── VerifyAVote (Logic) - 1.188ms
        │   ├── VerifyAVote_1 (Logic) - 1.181ms
        │   ├── VerifyAVote_2 (Logic) - 1.18ms
        │   └── VerifyAVote_3 (Logic) - 1.18ms
        ├── Tally_1_ShuffleRegistrationRecords (Logic) - 13.844ms
        │   ├── Shuffle (Logic) - 1.482ms
        │   ├── ShuffleVerify (Logic) - 1.884ms
        │   ├── Shuffle_1 (Logic) - 1.528ms
        │   ├── ShuffleVerify_1 (Logic) - 1.804ms
        │   ├── Shuffle_2 (Logic) - 1.752ms
        │   ├── ShuffleVerify_2 (Logic) - 1.821ms
        │   ├── Shuffle_3 (Logic) - 1.533ms
        │   └── ShuffleVerify_3 (Logic) - 1.933ms
        ├── Tally_2_DeterministicTagsOnShuffledRegistrationRecords (Logic) - 9.601ms
        │   ├── AdditiveBlinding (Logic) - 1.556ms
        │   └── Re-masking&PartialDecryption (Logic) - 8.033ms
        ├── Tally_3_ShuffleVotingRecords (Logic) - 49.126ms
        │   ├── Shuffle (Logic) - 6.223ms
        │   ├── ShuffleVerify (Logic) - 6.15ms
        │   ├── Shuffle_1 (Logic) - 6.251ms
        │   ├── ShuffleVerify_1 (Logic) - 6.265ms
        │   ├── Shuffle_2 (Logic) - 6.143ms
        │   ├── ShuffleVerify_2 (Logic) - 6.21ms
        │   ├── Shuffle_3 (Logic) - 5.888ms
        │   └── ShuffleVerify_3 (Logic) - 5.919ms
        ├── Tally_4_DeterministicTagsOnShuffledVotingRecords (Logic) - 17.119ms
        │   ├── AdditiveBlinding (Logic) - 1.533ms
        │   └── Re-masking&PartialDecryption (Logic) - 15.569ms
        ├── Tally_5_FilterRealVotes (Logic) - 44µs
        ├── Tally_6_DecryptVotes (Logic) - 4.878ms
        │   ├── MultiKeyDecryptWithProof (Logic) - 1.07ms
        │   ├── VerifyDecryptionProofs (Logic) - 1.369ms
        │   ├── MultiKeyDecryptWithProof_1 (Logic) - 988µs
        │   └── VerifyDecryptionProofs_1 (Logic) - 1.409ms
        └── Tally_7_TallyResults (Logic) - 1µs
```

---

## Reproducibility

### Testbed Environment

The primary experiments for our SOSP paper were conducted on the **SPHERE** testbed.

> **SPHERE (Security and Privacy Heterogeneous Environment for Reproducible Experimentation)** is a project funded by the National Science Foundation.
> -   **Hardware**: AMD EPYC 7702
> -   **Assigned Resources**: 4 cores, 36GB RAM

### Peripheral Requirements

Running the simulation in the full **`Peripheral`** hardware mode has critical dependencies:

-   **Printing**: A **modified version of CUPS** is required for precise performance measurements of the print-to-cut lifecycle.
-   **Camera/Scanner**:
    -   **macOS**: `imagesnap` (`brew install imagesnap`).
    -   **Raspberry Pi**: `libcamera-still`.
    -   Other platforms can be supported by editing the `GetImageCommand` function in `pkg/config/config.go`.

### Command-Line Arguments

```bash
./simulation --voters 10 --fake-creds 0 --runs 5
```

- On each run, increase voters by a factor of 10

### Results


| Voters      | Setup   | Registration   | Voting   | Tally   |
|-------------|---------|----------------|----------|---------|
| 10          |         |                |          |         |
| 100         |         |                |          |         |
| 1,000       |         |                |          |         |
| 10,000      |         |                |          |         |
| 100,000     |         |                |          |         |
| 1,000,000   |         |                |          |         |


## Papers

The following papers are related to Votegral and TRIP:

-   `L. Merino et al., "E-Vote Your Conscience: Perceptions of Coercion and Vote Buying, and the Usability of Fake Credentials in Online Voting," in 2024 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2024, pp. 3478-3496, doi: 10.1109/SP54263.2024.00252.`
-   `L. Merino et al., TRIP: Coercion-Resistant In-Person Registration for E-Voting with Verifiability and Usability in Votegral. To appear in the 31st ACM Symposium on Operating Systems Principles (SOSP 2025), Seoul, Republic of Korea, 2025`

## Acknowledgments

The use of AI (ChatGPT and Gemini) to ensure robust code quality and documentation for archival purposes.