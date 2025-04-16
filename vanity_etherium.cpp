#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#include "keccak-tiny.h"

struct SharedState {
    std::mutex mutex;
    std::condition_variable cv;
    bool foundMatch = false;
    std::vector<uint8_t> privateKey;
    std::string address;
    std::atomic<uint64_t> totalAttempts{0};
};

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> generateRandomPrivateKey() {
    std::vector<uint8_t> privateKey(32, 0);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    
    // Fill with random bytes
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t value = dis(gen);
        for (size_t j = 0; j < 8 && i + j < 32; ++j) {
            privateKey[i + j] = static_cast<uint8_t>((value >> (8 * j)) & 0xFF);
        }
    }
    
    return privateKey;
}

std::vector<uint8_t> derivePublicKey(const std::vector<uint8_t>& privateKey) {
    std::vector<uint8_t> publicKey;
    
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        throw std::runtime_error("Failed to create EC_KEY");
    }
    
    BIGNUM* priv = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!priv) {
        EC_KEY_free(key);
        throw std::runtime_error("Failed to convert private key to BIGNUM");
    }
    
    if (!EC_KEY_set_private_key(key, priv)) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to set private key");
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to create EC_POINT");
    }
    
    if (!EC_POINT_mul(group, pub_point, priv, nullptr, nullptr, nullptr)) {
        EC_POINT_free(pub_point);
        BN_free(priv);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to compute public key");
    }
    
    EC_KEY_set_public_key(key, pub_point);
    
    uint8_t* pub_bytes = nullptr;
    size_t pub_len = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &pub_bytes, nullptr);
    
    if (pub_len > 0 && pub_bytes) {
        publicKey.assign(pub_bytes, pub_bytes + pub_len);
        OPENSSL_free(pub_bytes);
    }
    
    EC_POINT_free(pub_point);
    BN_free(priv);
    EC_KEY_free(key);
    
    return publicKey;
}

std::string deriveEthereumAddress(const std::vector<uint8_t>& publicKey) {
    std::vector<uint8_t> keyWithoutPrefix(publicKey.begin() + 1, publicKey.end());
    
    std::vector<uint8_t> hash(32);
    keccak256(hash.data(), hash.size(), keyWithoutPrefix.data(), keyWithoutPrefix.size());
    
    std::vector<uint8_t> addressBytes(hash.end() - 20, hash.end());
    
    return "0x" + bytesToHex(addressBytes);
}

void workerThread(SharedState& state, 
                 const std::string& startPrefix, 
                 const std::string& endPrefix,
                 int threadId) {
    std::random_device rd;
    std::mt19937_64 gen(rd() + threadId); 
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    
    uint64_t localAttempts = 0;
    
    while (true) {
        {
            std::unique_lock<std::mutex> lock(state.mutex);
            if (state.foundMatch) {
                break;
            }
        }
        
        localAttempts++;
        if (localAttempts % 1000 == 0) {
            state.totalAttempts += 1000;
        }
        
        std::vector<uint8_t> privateKey(32, 0);
        for (size_t i = 0; i < 32; i += 8) {
            uint64_t value = dis(gen);
            for (size_t j = 0; j < 8 && i + j < 32; ++j) {
                privateKey[i + j] = static_cast<uint8_t>((value >> (8 * j)) & 0xFF);
            }
        }
        
        std::vector<uint8_t> publicKey = derivePublicKey(privateKey);
        
        std::string address = deriveEthereumAddress(publicKey);
        
        // Remove "0x" prefix for checking
        std::string addressWithoutPrefix = address.substr(2);
        
        // Convert to lowercase for case-insensitive comparison
        std::string lowerAddress = addressWithoutPrefix;
        std::transform(lowerAddress.begin(), lowerAddress.end(), lowerAddress.begin(), ::tolower);
        
        std::string lowerStartPrefix = startPrefix;
        std::transform(lowerStartPrefix.begin(), lowerStartPrefix.end(), lowerStartPrefix.begin(), ::tolower);
        
        std::string lowerEndPrefix = endPrefix;
        std::transform(lowerEndPrefix.begin(), lowerEndPrefix.end(), lowerEndPrefix.begin(), ::tolower);
        
        // Check if address starts with startPrefix and ends with endPrefix
        bool startMatches = lowerAddress.substr(0, lowerStartPrefix.length()) == lowerStartPrefix;
        bool endMatches = true;
        
        // Only check end if endPrefix is specified
        if (!endPrefix.empty()) {
            if (lowerAddress.length() >= lowerEndPrefix.length()) {
                endMatches = lowerAddress.substr(lowerAddress.length() - lowerEndPrefix.length()) == lowerEndPrefix;
            } else {
                endMatches = false;
            }
        }
        
        if (startMatches && endMatches) {
            std::unique_lock<std::mutex> lock(state.mutex);
            if (!state.foundMatch) {
                state.foundMatch = true;
                state.privateKey = privateKey;
                state.address = address;
                state.totalAttempts += (localAttempts % 1000);
                
                state.cv.notify_all();
            }
            break;
        }
    }
}

void progressReporter(SharedState& state) {
    uint64_t lastReported = 0;
    
    while (true) {
        {
            std::unique_lock<std::mutex> lock(state.mutex);
            if (state.foundMatch) {
                break;
            }
            
            uint64_t current = state.totalAttempts.load();
            if (current - lastReported >= 10000) {
                std::cout << "Attempts: " << current << " (" 
                          << (current - lastReported) / 10 << "K/s)\r" << std::flush;
                lastReported = current;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <start_prefix> [end_prefix] [num_threads=0]" << std::endl;
        std::cerr << "Example: " << argv[0] << " abc def 8" << std::endl;
        std::cerr << "Note: num_threads=0 will use all available CPU cores" << std::endl;
        std::cerr << "Note: Matching is case-insensitive" << std::endl;
        return 1;
    }
    
    std::string startPrefix = argv[1];
    std::string endPrefix = (argc > 2) ? argv[2] : "";
    
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (argc > 3) {
        int requested = std::stoi(argv[3]);
        if (requested > 0) {
            numThreads = requested;
        }
    }
    
    numThreads = std::max(1u, numThreads);
    
    // Remove 0x if present in the prefixes
    if (startPrefix.substr(0, 2) == "0x") {
        startPrefix = startPrefix.substr(2);
    }
    
    if (!endPrefix.empty() && endPrefix.substr(0, 2) == "0x") {
        endPrefix = endPrefix.substr(2);
    }
    
    std::cout << "Searching for Ethereum address with:" << std::endl;
    std::cout << "  Start prefix: 0x" << startPrefix << std::endl;
    if (!endPrefix.empty()) {
        std::cout << "  End suffix:   " << endPrefix << std::endl;
    }
    std::cout << "Using " << numThreads << " threads" << std::endl;
    std::cout << "Press Ctrl+C to stop at any time..." << std::endl;
    
    SharedState state;
    
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(workerThread, std::ref(state), std::ref(startPrefix), std::ref(endPrefix), i);
    }
    
    std::thread reporter(progressReporter, std::ref(state));
    
    for (auto& t : threads) {
        t.join();
    }
    
    reporter.join();
    
    std::string privateKeyHex = bytesToHex(state.privateKey);
    
    std::cout << std::endl;
    std::cout << "Found matching address after " << state.totalAttempts.load() << " attempts!" << std::endl;
    std::cout << "Address: " << state.address << std::endl;
    if (!endPrefix.empty()) {
        std::cout << "Matches: Start=" << startPrefix << ", End=" << endPrefix << std::endl;
    } else {
        std::cout << "Matches prefix: " << startPrefix << std::endl;
    }
    std::cout << "Private Key: 0x" << privateKeyHex << std::endl;
    std::cout << "You can import this private key into your wallet." << std::endl;
    
    return 0;
}
