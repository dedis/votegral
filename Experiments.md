## Experiments

### Testbed Environment

The primary experiments for our SOSP paper were conducted on the **SPHERE** testbed.

> **SPHERE [1] (Security and Privacy Heterogeneous Environment for Reproducible Experimentation)** - a project funded by the National Science Foundation.
> -   **Hardware**: AMD EPYC 7702
> -   **Assigned Resources**: Metal: 128 cores, 256GB RAM

### Results

#### Core w/ No Fake Credentials

```bash
./simulation --runs 5 --ea-members 4 --shuffle BayerGroth --cores 0 --print-metrics --max-depth 2 --hw Core --fake-creds 0 --voters 10
```

| Voters  | Total            | Setup       | Registration  | Voting        | Tally            |
|---------|------------------|-------------|---------------|---------------|------------------|
| 10      | 1.058657s        | 471µs       | 11.554ms      | 9.226ms       | 1.036441s        |
| 100     | 7.306084s        | 4.766ms     | 164.169ms     | 141.097ms     | 6.996051s        |
| 1000    | 52.822079s       | 90.115ms    | 1.459245s     | 1.07366s      | 50.241299s       |
| 10000   | 8m36.123987s     | 618.907ms   | 12.94649s     | 9.647732s     | 8m12.535303s     |
| 100000  | 1h25m26.909434s  | 6.209704s   | 2m6.132749s   | 1m34.237212s  | 1h21m39.664007s  |
| 1000000 | 14h15m29.629007s | 1m4.169733s | 20m57.314222s | 15m40.314659s | 13h37m46.561243s |

#### Core w/ 1 Fake Credential & Vote Per Voter

```bash
./simulation --runs 5 --ea-members 4 --shuffle BayerGroth --cores 0 --print-metrics --max-depth 2 --hw Core --fake-creds 1 --voters 10
```

| Voters  | Total            | Setup        | Registration  | Voting        | Tally            |
|---------|------------------|--------------|---------------|---------------|------------------|
| 10      | 1.489454s        | 1.947ms      | 29.019ms      | 18.405ms      | 1.435193s        |
| 100     | 9.670272s        | 19.232ms     | 346.617ms     | 255.513ms     | 9.094443s        |
| 1000    | 1m20.90646s      | 143.768ms    | 2.598043s     | 2.100961s     | 1m15.977176s     |
| 10000   | 13m9.220823s     | 1.270037s    | 24.099981s    | 19.150172s    | 12m24.872327s    |
| 100000  | 2h12m12.372249s  | 12.445885s   | 3m57.137945s  | 3m8.414851s   | 2h4m53.532549s   |
| 1000000 | 21h58m30.521827s | 2m15.822436s | 39m25.126282s | 31m21.737368s | 20h45m27.820265s |


#### Disk w/ No Fake Credentials

```bash
rm -rf output/pics && ./simulation --runs 5 --ea-members 4 --shuffle BayerGroth --cores 0 --print-metrics --max-depth 2 --hw Disk --fake-creds 0 --voters 10
```

| Voters  | Total         | Setup      | Registration  | Voting    | Tally        |
|---------|---------------|------------|---------------|-----------|--------------|
| 10      | 4.123436s     | 243.984ms  | 2.808725s     | 20.407ms  | 1.10572s     |
| 100     | 35.255889s    | 2.683711s  | 25.568202s    | 146.413ms | 6.882406s    |
| 1000    | 3m51.74037s   | 17.529219s | 2m43.509778s  | 1.011406s | 49.664355s   |
| 10000   | 32m56.313596s | 2m6.94623s | 22m24.209319s | 9.483368s | 8m12.774162s |


#### Disk w/ 1 Fake Credential & Vote Per Voter

```bash
rm -rf output/pics && ./simulation --runs 5 --ea-members 4 --shuffle BayerGroth --cores 0 --print-metrics --max-depth 2 --hw Disk --fake-creds 1 --voters 10
```

| Voters  | Total         | Setup       | Registration  | Voting     | Tally         |
|---------|---------------|-------------|---------------|------------|---------------|
| 10      | 7.008678s     | 531.109ms   | 5.033308s     | 40.406ms   | 1.37484s      |
| 100     | 56.218387s    | 5.232633s   | 41.733236s    | 239.391ms  | 9.024442s     |
| 1000    | 6m27.722182s  | 32.380437s  | 4m37.65937s   | 1.957813s  | 1m15.539258s  |
| 10000   | 56m30.774012s | 4m8.266115s | 39m40.759346s | 18.771588s | 12m27.050688s |

## Citations

[1] Goodfellow, Ryan, Lincoln Thurlow, and Srivatsan Ravi. 
"Merge: An architecture for interconnected testbed ecosystems." 
arXiv preprint arXiv:1810.08260 (2018).