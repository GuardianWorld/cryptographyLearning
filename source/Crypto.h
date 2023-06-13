#include <iostream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

class cryptography{
private: 
    const CryptoPP::SecByteBlock saltKey;
    const CryptoPP::SecByteBlock privKey;
public:
    cryptography(int iter, int keyLenght, const CryptoPP::SecByteBlock& sKey, const CryptoPP::SecByteBlock& pKey);
    cryptography(int iter, int keyLenght, int saltLenght, std::string* password);
    CryptoPP::SecByteBlock generateSalt(int saltLength);
    CryptoPP::SecByteBlock generateKey(std::string password, int derivedKeyLenght, int iterations);
    std::string encodedHex(CryptoPP::SecByteBlock key);
    std::string encrypt(const std::string& plaintext) const;
    std::string decrypt(const std::string& ciphertext) const;

    CryptoPP::SecByteBlock getSalt();
    CryptoPP::SecByteBlock getKey();
};