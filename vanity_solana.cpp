#include <sodium.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <cctype>
#include <algorithm>

const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::atomic<long long> globalAttempts(0);

std::string base58_encode(const unsigned char* input, size_t len) {
    std::string result;
    result.reserve(64);

    std::vector<unsigned char> digits;
    digits.reserve(64);
    digits.push_back(0);

    for (size_t i = 0; i < len; ++i) {
        int carry = input[i];
        for (size_t j = 0; j < digits.size(); ++j) {
            carry += digits[j] * 256;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    for (size_t i = 0; i < len && input[i] == 0; ++i)
        result.push_back(BASE58_ALPHABET[0]);

    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        result.push_back(BASE58_ALPHABET[*it]);

    return result;
}

// New function that checks if a string starts with a prefix, with an option for case sensitivity.
bool starts_with(const std::string& str, const std::string& prefix, bool caseSensitive) {
    // std::cout << str << std::endl;
    // std::cout << prefix << std::endl;

    if (prefix.size() > str.size()) return false;
    if (caseSensitive) {
        return std::equal(prefix.begin(), prefix.end(), str.begin());
    } else {
        for (size_t i = 0; i < prefix.size(); i++) {
            if (std::tolower(static_cast<unsigned char>(str[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
                return false;
        }
        return true;
    }
}

void worker(const std::string& targetPrefix, bool caseSensitive, std::atomic<bool>& found, std::mutex& outMutex, int threadId) {
    unsigned char seed[32];
    unsigned char pk[32], sk[64];

    long long localAttempts = 0;

    while (!found.load()) {
        randombytes_buf(seed, 32);
        crypto_sign_seed_keypair(pk, sk, seed);
        std::string pubkeyBase58 = base58_encode(pk, 32);

        localAttempts++;

        if (localAttempts >= 100000) {
            long long local = localAttempts;
            localAttempts = 0;
            long long total = globalAttempts.fetch_add(local) + local;
            if (total % 1000000 == 0) {
                std::lock_guard<std::mutex> lock(outMutex);
                std::cout << "[Total Attempts: " << total << "]" << std::endl;
            }
        }

        if (starts_with(pubkeyBase58, targetPrefix, caseSensitive)) {
            found.store(true);
            std::lock_guard<std::mutex> lock(outMutex);
            std::cout << "\n🎉 Thread " << threadId << " found a match!" << std::endl;
            std::cout << "Public Key: " << pubkeyBase58 << std::endl;
            std::string privkeyBase58 = base58_encode(sk, 64);
            std::cout << "Private Key (base58): " << privkeyBase58 << std::endl;
            break;
        }
    }
}

std::string multiplyStringByInt(const std::string& numStr, int multiplier) {
    std::string result;
    int carry = 0;

    for (int i = numStr.size() - 1; i >= 0; --i) {
        int digit = numStr[i] - '0';
        int product = digit * multiplier + carry;
        result += (product % 10) + '0';
        carry = product / 10;
    }

    while (carry) {
        result += (carry % 10) + '0';
        carry /= 10;
    }

    std::reverse(result.begin(), result.end());
    return result;
}

std::string powerOf58(int exponent) {
    std::string result = "1";
    for (int i = 0; i < exponent; ++i) {
        result = multiplyStringByInt(result, 58);
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <prefix> <case_sensitive (1 or 0)>" << std::endl;
        return 1;
    }

    const std::string prefix(argv[1]);
    int caseSensitivityFlag = std::stoi(argv[2]);
    bool caseSensitive = (caseSensitivityFlag == 1);

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium." << std::endl;
        return 1;
    }

    const int numThreads = std::thread::hardware_concurrency();
    std::cout << "🔍 Searching for public key starting with: " << prefix << std::endl;
    std::cout << "🔎 Case sensitive: " << (caseSensitive ? "Yes" : "No") << std::endl;
    std::cout << "🧵 Using " << numThreads << " threads...\n";

    const int exponent = prefix.length();
    std::string result = powerOf58(exponent);
    std::cout << "Attempts needed for guarantee chance: " << result << std::endl;

    std::atomic<bool> found(false);
    std::mutex outputMutex;
    std::vector<std::thread> threads;

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(worker, prefix, caseSensitive, std::ref(found), std::ref(outputMutex), i);
    }

    for (auto& t : threads) {
        t.join();
    }

    return 0;
}
