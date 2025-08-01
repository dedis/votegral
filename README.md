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

---

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
-   **`pkg/`**: Contains all the core, reusable packages that define the Votegral system.
    -   **`actors/`**: Defines participants in the election, such as the `ElectionAuthority`, `Voter`, and `RegistrationKiosk`.
    -   **`config/`**: Manages simulation configuration from command-line flags.
    -   **`context/`**: Provides a shared context for operations, carrying request-scoped data like loggers and metric recorders.
    -   **`crypto/`**: Implements the fundamental cryptographic primitives for digital signatures (Schnorr) and encryption (M-ElGamal) over the Ed25519 curve.
    -   **`hardware/`**: Provides an abstraction layer for interacting with physical or simulated hardware like QR code scanners and printers.
    -   **`ledger/`**: Implements the append-only, immutable ledger for transparently recording all critical election events.
    -   **`log/`**: Contains a custom, structured, and leveled logging implementation.
    -   **`metrics/`**: Provides tools for recording and aggregating performance metrics (e.g., CPU time, memory) for various operations.
    -   **`protocol/`**: Orchestrates the high-level cryptographic protocols for registration, activation, and voting.
    -   **`result/`**: Manages the formatting and writing of simulation results into CSV files.
-   **`output/`**: The default directory for all generated artifacts, including performance data and QR code images.

## Configuration

The simulation's behavior is controlled via command-line flags.

### Command Line Arguments

| Flag            | Type   | Default          | Description                                                               |
|-----------------|--------|------------------|---------------------------------------------------------------------------|
| --voters        | uint64 | 100              | Number of voters.                                                         |
| --fake-creds    | uint64 | 1                | Number of fake credentials per voter                                      |
| --talliers      | uint64 | 4                | Number of Election Authority Members (Talliers)                           |
| --hwType        | string | Core             | [Hardware modes](#hardware-configuration) (`Core`, `Disk`, `Peripherals`) |
| --system        | string | Mac              | System name for system-specific logic                                     |
| --logLevel      | string | info             | Set log level (`trace`, `debug`, `info`, `error`)                         |
| --seed          | string | votegral         | Seed value for all randomly generated values                              |
| --printer       | string | TM               | Name of the printer in CUPS if Peripheral is enabled                      |
| --pics          | string | "output/pics"    | Path for storing pictures of physical materials                           |
| --results       | string | "output/results" | Path for storing simulation results                                       |
| --print-metrics | string | false            | Whether to print detailed metrics during execution                        |
| --cups-wait     | int    | 100              | Wait time (ms) for CUPS daemon to start for measurement.                  |


### Hardware Modes

The simulation can run in different hardware modes, configured via the `-hw` flag:

-   **`Core`**: An in-memory mock that performs no external I/O. This is the fastest mode and is ideal for benchmarking the core cryptographic protocol.
-   **`Disk`**: Simulates I/O by writing and reading QR code files to and from the disk. This measures the overhead of file system operations.
-   **`Peripheral`**: Enables interaction with physical hardware like printers and cameras, providing the most realistic performance data.

### Simulation Output

-   **Performance Data**: The simulation generates detailed performance and resource usage data in CSV format, saved to the directory specified by the `-results` flag (default: `output/results/`). Both raw, per-operation data and aggregated statistical results are provided.
-   **Physical Artifacts**: If using `Disk` or `Peripheral` modes, generated QR codes are saved as PDF/image files in the `-pics` directory (default: `output/pics/`).

---

## Reproducibility

### Testbed Environment

The primary experiments for our paper were conducted on the **SPHERE** testbed.

> **SPHERE (Security and Privacy Heterogeneous Environment for Reproducible Experimentation)** is a project funded by the National Science Foundation.
> -   **Hardware**: AMD EPYC 7702
> -   **Assigned Resources**: 4 cores, 36GB RAM

The peripheral experiments for our paper were conducted on a Macbook Pro.

### Peripheral Requirements

Running the simulation in the full **`Peripheral`** hardware mode has critical dependencies:

-   **Printing**: A **modified version of CUPS** is required for precise performance measurements of the print-to-cut lifecycle.
-   **Camera/Scanner**:
    -   **macOS**: `imagesnap` (`brew install imagesnap`).
    -   **Raspberry Pi**: `libcamera-still`.
    -   Other platforms can be supported by editing the `GetImageCommand` function in `pkg/config/config.go`.

### Command-Line Arguments

```bash
cd cmd/simulation
go build .
./simulation --voters 10 --fake-creds 0
```

- On each run, increase voters by a factor of 10

### Results

| Voters    | Setup | Registration | Voting | Tally |
|-----------|-------|--------------|--------|-------|
| 10        |       |              |        |       |
| 100       |       |              |        |       |
| 1,000     |       |              |        |       |
| 10,000    |       |              |        |       |
| 100,000   |       |              |        |       |
| 1,000,000 |       |              |        |       |


## Papers

The following papers are related to Votegral and TRIP:

-   `L. Merino et al., "E-Vote Your Conscience: Perceptions of Coercion and Vote Buying, and the Usability of Fake Credentials in Online Voting," in 2024 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2024, pp. 3478-3496, doi: 10.1109/SP54263.2024.00252.`
-   `L. Merino et al., TRIP: Coercion-Resistant In-Person Registration for E-Voting with Verifiability and Usability in Votegral. To appear in the 31st ACM Symposium on Operating Systems Principles (SOSP 2025), Seoul, Republic of Korea, 2025`

## Acknowledgments

The use of AI (ChatGPT and Gemini) to ensure robust code quality and documentation for archival purposes.
