#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#define S256 32
#define defaultFile "keys.bin"

class cryptography{
private: 
    CryptoPP::SecByteBlock saltKey;
    CryptoPP::SecByteBlock privKey;
    int iterations;


    std::string generateHash(const CryptoPP::SecByteBlock& value);
    CryptoPP::SecByteBlock generateSalt(int saltLength);
    CryptoPP::SecByteBlock generateKey(std::string password, int derivedKeyLenght, int iterations);
    void saveHashAndSalt(const std::string& filename, std::string hashedSafe);
    CryptoPP::SecByteBlock retrieveHashAndSalt(const std::string& filename);
    
public:

    cryptography(int iter, std::string* password, std::string* safeValue);
    cryptography();
    
    bool login(int iter, const std::string& keyFile, std::string* password, std::string* safeValue);

    std::string encodedHex(CryptoPP::SecByteBlock key);
    std::string encodedHex(std::string key);
    
    std::string encrypt(const std::string& plaintext) const;
    std::string decrypt(const std::string& ciphertext) const;
    void encryptFile(const std::string& inputFile, const std::string& outputFile) const;
    void decryptFile(const std::string& inputFile, const std::string& outputFile) const;

    CryptoPP::SecByteBlock getSalt();
    CryptoPP::SecByteBlock getKey();
};