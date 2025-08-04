// START: Groth Shuffle Application for Votegral

#include "shuffler.h"
#include "curve.h"

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <map>

const size_t SCALAR_BYTE_SIZE = 32;
const size_t POINT_BYTE_SIZE = 65; // Uncompressed Kyber format

// --- Base64 ---

// base64_encodes encodes data into base64.
static std::string base64_encode(const std::vector<uint8_t>& in) {
    std::string out;
    const std::string base64_chars =
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789+/";

    int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

// base64_decode decodes base64 string stored in files.
static std::vector<uint8_t> base64_decode(const std::string& in) {
    std::vector<uint8_t> out;
    const std::string base64_chars =
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789+/";

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[base64_chars[i]] = i;

    int val=0, valb=-8;
    for (char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(uint8_t((val>>valb)&0xFF));
            valb -= 8;
        }
    }
    return out;
}

// --- Kyber/Relic Adapter Functions ---

// Adapter for Scalars (Relic/SHF Scalar to Kyber bytes)
std::vector<uint8_t> relic_to_kyber_scalar(const shf::Scalar& s) {
    std::vector<uint8_t> kyber_bytes(SCALAR_BYTE_SIZE);
    // Get a constant pointer to the underlying bn_t representation of the scalar.
    const bn_t* src_ptr = reinterpret_cast<const bn_t*>(&s);
    // Write the bignum into the byte vector in big-endian format.
    bn_write_bin(kyber_bytes.data(), SCALAR_BYTE_SIZE, *src_ptr);
    return kyber_bytes;
}

// Adapter for Scalars (Kyber bytes to Relic/SHF Scalar)
shf::Scalar kyber_to_relic_scalar(const std::vector<uint8_t>& kyber_bytes) {
    if (kyber_bytes.size() != SCALAR_BYTE_SIZE) {
        throw std::runtime_error("Invalid Kyber scalar size.");
    }
    bn_t temp_scalar;
    bn_new(temp_scalar);
    // Rehad binary data into te Relic bignum format.
    bn_read_bin(temp_scalar, kyber_bytes.data(), kyber_bytes.size());

    shf::Scalar result;
    // Assumes shf::Scalar is compatible with bn_t for copying.
    bn_copy(*reinterpret_cast<bn_t*>(&result), temp_scalar);
    bn_free(temp_scalar);
    return result;
}

shf::Point kyber_to_relic_point(const std::vector<uint8_t>& kyber_bytes) {
    if (kyber_bytes.size() != 65) {
        throw std::runtime_error("Invalid Kyber point size. Expected 65 bytes.");
    }
    if (kyber_bytes[0] != 0x04) {
        throw std::runtime_error("Invalid Kyber point format. Expected uncompressed prefix 0x04.");
    }
    ec_t temp_point;
    ec_new(temp_point);
    ec_read_bin(temp_point, kyber_bytes.data(), kyber_bytes.size());
    shf::Point result;
    ec_copy(*reinterpret_cast<ec_t*>(&result), temp_point);
    ec_free(temp_point);
    return result;
}

std::vector<uint8_t> relic_to_kyber_point(const shf::Point& p) {
    // Create a temporary point to hold the normalized (affine) version.
    ec_t norm_point;
    ec_new(norm_point);

    // Get a pointer to the source point (which may be in Jacobian coordinates).
    const ep_st* src_ptr = reinterpret_cast<const ep_st*>(&p);

    // Normalize the source point into our temporary point.
    ec_norm(norm_point, src_ptr);

    std::vector<uint8_t> kyber_bytes(65);
    kyber_bytes[0] = 0x04;

    if (ec_is_infty(norm_point)) {
        std::memset(kyber_bytes.data() + 1, 0, 64);
    } else {
        bn_t x, y;
        bn_new(x);
        bn_new(y);
        // Get coordinates from the affine point.
        ec_get_x(x, norm_point);
        ec_get_y(y, norm_point);
        bn_write_bin(kyber_bytes.data() + 1, 32, x);
        bn_write_bin(kyber_bytes.data() + 33, 32, y);
        bn_free(x);
        bn_free(y);
    }

    // Clean up the temporary point.
    ec_free(norm_point);

    return kyber_bytes;
}

// --- File Reading/Writing ---
// Various methods to write and read from files between Kyber and relic.

// Writes a file containing base64 encoded ciphertexts (C1,C2), one per line.
void write_ciphertexts_to_file_kyber(const std::vector<shf::Ctxt>& ctxts, const std::string& filename) {
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not open file " << filename << " for writing." << std::endl;
        return;
    }
    outfile << "c1_base64,c2_base64\n";
    for (const auto& ctxt : ctxts) {
        std::vector<uint8_t> u_kyber = relic_to_kyber_point(ctxt.U);
        std::vector<uint8_t> v_kyber = relic_to_kyber_point(ctxt.V);
        outfile << base64_encode(u_kyber) << "," << base64_encode(v_kyber) << "\n";
    }
    outfile.close();
}

// Reads a file containing base64 encoded ciphertexts (C1,C2), one per line.
std::vector<shf::Ctxt> read_ciphertexts_from_file(const std::string& filename) {
    std::vector<shf::Ctxt> loaded_ctxts;
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Error: Could not open file " + filename + " for reading.");
    }
    std::string line;
    std::getline(infile, line); // Skip header
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        size_t comma_pos = line.find(',');
        if (comma_pos == std::string::npos) { continue; }
        std::string u_base64 = line.substr(0, comma_pos);
        std::string v_base64 = line.substr(comma_pos + 1);
        std::vector<uint8_t> u_bytes = base64_decode(u_base64);
        std::vector<uint8_t> v_bytes = base64_decode(v_base64);
        shf::Point U = kyber_to_relic_point(u_bytes);
        shf::Point V = kyber_to_relic_point(v_bytes);
        loaded_ctxts.push_back({U, V});
    }
    infile.close();
    std::cout << "Successfully read " << loaded_ctxts.size() << " ciphertexts from " << filename << std::endl;
    return loaded_ctxts;
}

// Reads a file containing base64 encoded scalars (randomness), one per line.
std::vector<shf::Scalar> read_randomness_from_file(const std::string& filename) {
    std::vector<shf::Scalar> loaded_scalars;
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Error: Could not open randomness file " + filename);
    }
    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        std::vector<uint8_t> bytes = base64_decode(line);
        shf::Scalar s = kyber_to_relic_scalar(bytes);
        loaded_scalars.push_back(s);
    }
    infile.close();
    return loaded_scalars;
}

// Reads a file containing the permutation (integers), one index per line.
shf::Permutation read_permutation_from_file(const std::string& filename) {
    shf::Permutation permutation;
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Error: Could not open permutation file " + filename);
    }
    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;
        try {
            long index = std::stol(line);
            if (index < 0) throw std::runtime_error("Negative index found");
            permutation.push_back(static_cast<std::size_t>(index));
        } catch (const std::exception& e) {
            throw std::runtime_error("Error parsing permutation integer.");
        }
    }
    infile.close();

    // Validate that it is a valid permutation (contains 0 to N-1 exactly once)
    std::vector<std::size_t> sorted_p = permutation;
    std::sort(sorted_p.begin(), sorted_p.end());
    for (std::size_t i = 0; i < sorted_p.size(); ++i) {
        if (sorted_p[i] != i) {
            throw std::runtime_error("Invalid permutation sequence provided.");
        }
    }
    return permutation;
}

// Reads a file containing the public key that the ElGamal ciphertext is encrypted to
// In other words, the election authority's public key
shf::PublicKey read_public_key_from_file(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Error: Could not open public key file " + filename);
    }
    std::string pk_base64;
    std::getline(infile, pk_base64);

    std::vector<uint8_t> pk_bytes = base64_decode(pk_base64);
    shf::PublicKey pk = kyber_to_relic_point(pk_bytes);

    std::cout << "Successfully read public key from " << filename << std::endl;
    return pk;
}

// --- Proof objects ---
// Various methods to write and read points for proof.
// Under construction. Unsuccessful at saving and loading proofs.
// Instead, the Prover will both Prove and Verify to get total latency
// of both operations.

void write_point(std::ofstream& out, const shf::Point& p) {
    auto bytes = relic_to_kyber_point(p);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

shf::Point read_point(std::ifstream& in) {
    std::vector<uint8_t> bytes(POINT_BYTE_SIZE);
    in.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    return kyber_to_relic_point(bytes);
}

void write_scalar(std::ofstream& out, const shf::Scalar& s) {
    auto bytes = relic_to_kyber_scalar(s); // Assumes you implemented this
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

shf::Scalar read_scalar(std::ifstream& in) {
    std::vector<uint8_t> bytes(SCALAR_BYTE_SIZE);
    in.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    return kyber_to_relic_scalar(bytes);
}

// Helper for writing a vector of scalars
void write_scalar_vector(std::ofstream& out, const std::vector<shf::Scalar>& vec) {
    size_t vec_size = vec.size();
    out.write(reinterpret_cast<const char*>(&vec_size), sizeof(vec_size));
    for (const auto& s : vec) {
        write_scalar(out, s);
    }
}

// Helper for reading a vector of scalars
std::vector<shf::Scalar> read_scalar_vector(std::ifstream& in) {
    size_t vec_size;
    in.read(reinterpret_cast<char*>(&vec_size), sizeof(vec_size));
    std::vector<shf::Scalar> vec;
    vec.reserve(vec_size);
    for (size_t i = 0; i < vec_size; ++i) {
        vec.push_back(read_scalar(in));
    }
    return vec;
}

// Write proof to file
// Under construction.
void write_proof_to_file(const std::string& filename, const shf::ShuffleP& proof) {
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile.is_open()) throw std::runtime_error("Cannot open proof file for writing.");

    // --- Part 1: Main proof components ---
    write_point(outfile, proof.Ca);
    write_point(outfile, proof.Cb);

    // --- Part 2: Serialize ProductP (matching zkp.h) ---
    write_point(outfile, proof.product_proof.C0);
    write_point(outfile, proof.product_proof.C1);
    write_point(outfile, proof.product_proof.C2);
    write_scalar_vector(outfile, proof.product_proof.as);
    write_scalar_vector(outfile, proof.product_proof.bs);
    write_scalar(outfile, proof.product_proof.r);
    write_scalar(outfile, proof.product_proof.s);

    // --- Part 3: Serialize MultiExpP (matching zkp.h) ---
    write_point(outfile, proof.multiexp_proof.C0);
    write_point(outfile, proof.multiexp_proof.C1);
    write_point(outfile, proof.multiexp_proof.E.U); // Ctxt has two points
    write_point(outfile, proof.multiexp_proof.E.V);
    write_scalar_vector(outfile, proof.multiexp_proof.a);
    write_scalar(outfile, proof.multiexp_proof.r);
    write_scalar(outfile, proof.multiexp_proof.b);
    write_scalar(outfile, proof.multiexp_proof.s);
    write_scalar(outfile, proof.multiexp_proof.t);

    outfile.close();
}

// Read proof from file
// Under construction.
shf::ShuffleP read_proof_from_file(const std::string& filename, const std::vector<shf::Ctxt>& pEs) {
    std::ifstream infile(filename, std::ios::binary);
    if (!infile.is_open()) throw std::runtime_error("Cannot open proof file for reading.");

    shf::ShuffleP proof;
    proof.permuted = pEs; // The permuted ciphertexts are part of the statement

    // --- Part 1: Main proof components ---
    proof.Ca = read_point(infile);
    proof.Cb = read_point(infile);

    // --- Part 2: Deserialize ProductP (matching zkp.h) ---
    proof.product_proof.C0 = read_point(infile);
    proof.product_proof.C1 = read_point(infile);
    proof.product_proof.C2 = read_point(infile);
    proof.product_proof.as = read_scalar_vector(infile);
    proof.product_proof.bs = read_scalar_vector(infile);
    proof.product_proof.r = read_scalar(infile);
    proof.product_proof.s = read_scalar(infile);

    // --- Part 3: Deserialize MultiExpP (matching zkp.h) ---
    proof.multiexp_proof.C0 = read_point(infile);
    proof.multiexp_proof.C1 = read_point(infile);
    proof.multiexp_proof.E.U = read_point(infile);
    proof.multiexp_proof.E.V = read_point(infile);
    proof.multiexp_proof.a = read_scalar_vector(infile);
    proof.multiexp_proof.r = read_scalar(infile);
    proof.multiexp_proof.b = read_scalar(infile);
    proof.multiexp_proof.s = read_scalar(infile);
    proof.multiexp_proof.t = read_scalar(infile);

    infile.close();
    return proof;
}

// --- Parse command line arguments ---

std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 < argc) {
            args[argv[i]] = argv[i + 1];
        }
    }
    return args;
}

void print_usage() {
    std::cerr << "Usage: ./bayer_groth_tool <command> [options]\n"
              << "Commands:\n"
              << "  shuffle   --pk <file> --in <file> --out <file> --proof <file>\n"
              << "  prove     --pk <file> --in <file> --out <file> --perm <file> --rand <file> --proof <file>\n"
              << "  verify    --pk <file> --in <file> --out <file> --proof <file>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string command = argv[1];
    auto args = parse_args(argc, argv);

    try {
        shf::CurveInit();

        if (command == "shuffle") {
            // ./shuffle_app shuffle --pk pk.txt --in input.csv --out shuffled.csv --proof proof.bin
            auto pk = read_public_key_from_file(args.at("--pk"));
            auto ctxts = read_ciphertexts_from_file(args.at("--in"));

            shf::Prg prg;
            shf::Shuffler shuffler(pk, shf::CreateCommitKey(ctxts.size()), prg);
            shf::Hash hp;

            std::cout << "Shuffling and proving..." << std::endl;
            shf::ShuffleP proof = shuffler.Shuffle(ctxts, hp);

            write_ciphertexts_to_file_kyber(proof.permuted, args.at("--out"));
            write_proof_to_file(args.at("--proof"), proof);

            std::cout << "Verifying shuffle proof..." << std::endl;
            shf::Hash hv;
            bool correct = shuffler.VerifyShuffle(ctxts, proof, hv);

            if (correct) {
                std::cout << "Verification SUCCESS" << std::endl;
                return 0;
            } else {
                std::cout << "Verification FAILED" << std::endl;
                return 1;
            }

            std::cout << "SUCCESS: Shuffle and proof completed." << std::endl;

        } else if (command == "prove") {
            // ./shuffle_app prove --pk pk.txt --in in.csv --out out.csv --perm p.txt --rand r.txt --proof proof.bin
            auto pk = read_public_key_from_file(args.at("--pk"));
            auto in_ctxts = read_ciphertexts_from_file(args.at("--in"));
            auto out_ctxts = read_ciphertexts_from_file(args.at("--out"));
            auto p = read_permutation_from_file(args.at("--perm"));
            auto rho = read_randomness_from_file(args.at("--rand"));

            shf::Prg prg;
            shf::Shuffler shuffler(pk, shf::CreateCommitKey(in_ctxts.size()), prg);
            shf::Hash hp;

            std::cout << "Proving existing shuffle..." << std::endl;
            shf::ShuffleP proof = shuffler.Prove(in_ctxts, out_ctxts, p, rho, hp);

            write_proof_to_file(args.at("--proof"), proof);

            std::cout << "Verifying shuffle proof..." << std::endl;
            shf::Hash hv;
            bool correct = shuffler.VerifyShuffle(in_ctxts, proof, hv);

            if (correct) {
                std::cout << "Verification SUCCESS" << std::endl;
                return 0;
            } else {
                std::cout << "Verification FAILED" << std::endl;
                return 1;
            }

            std::cout << "SUCCESS: Proof generated." << std::endl;

        } else if (command == "verify") {
            // Under construction
            return 1;
            // ./shuffle_app verify --pk pk.txt --in in.csv --out out.csv --proof proof.bin
            auto pk = read_public_key_from_file(args.at("--pk"));
            auto in_ctxts = read_ciphertexts_from_file(args.at("--in"));
            auto out_ctxts = read_ciphertexts_from_file(args.at("--out"));
            auto proof = read_proof_from_file(args.at("--proof"), out_ctxts);

            shf::Prg prg;
            shf::Shuffler shuffler(pk, shf::CreateCommitKey(in_ctxts.size()), prg);
            shf::Hash hv;

            std::cout << "Verifying shuffle proof..." << std::endl;
            bool correct = shuffler.VerifyShuffle(in_ctxts, proof, hv);

            if (correct) {
                std::cout << "Verification SUCCESS" << std::endl;
                return 0;
            } else {
                std::cout << "Verification FAILED" << std::endl;
                return 1;
            }

        } else {
            std::cerr << "Error: Unknown command '" << command << "'\n";
            print_usage();
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

// END: Groth Shuffle Application for Votegral