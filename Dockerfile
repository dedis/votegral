# =========================================================================
# Votegral Dockerfile
# =========================================================================
FROM ubuntu:24.04

# Prevent apt-get from prompting for user input
ENV DEBIAN_FRONTEND=noninteractive

# apt-get dependencies
RUN apt-get update && apt-get install -y \
    vim git wget python3 python-is-python3 \
    build-essential cmake libgmp-dev

# Install Go
ENV GO_VERSION=1.23.11
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Copy repo to container
WORKDIR /app
COPY . .

# Dependency for BayerGroth Shuffle App
WORKDIR /app/prerequisites/anderspkd_groth-shuffle
RUN git clone https://github.com/catchorg/Catch2.git && \
    cd Catch2 && \
    git checkout v2.x && \
    cmake -B build -S . && \
    cmake --build build --target install

# Build BayerGroth Shuffle App and test.
RUN cmake . -B build && \
    cd build && \
    make && \
    make test && \
    ./tests.x

# Copy BayerGroth program to the main directory.
RUN cp /app/prerequisites/anderspkd_groth-shuffle/build/shuffle_app /app/cmd/simulation/

# Build Votegral
WORKDIR /app/cmd/simulation
RUN go build .

# Create the directories required by Votegral.
RUN mkdir -p /app/output/pics /app/output/results /app/output/tmp

# Default
ENTRYPOINT ["./simulation"]
CMD ["--runs=1", "--voters=100", "--hw=Core", "--shuffle=Neff", "--print-metrics"]