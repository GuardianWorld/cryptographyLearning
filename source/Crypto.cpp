#include "Crypto.h"

cryptography::cryptography(int iter, int keyLenght, int saltLenght, std::string* password):
saltKey(generateSalt(saltLenght)),
privKey(generateKey(*password, keyLenght, iter)){
    //Clear password
    std::fill(password->begin(), password->end(), 0);
    //delete password;
}


CryptoPP::SecByteBlock cryptography::getSalt(){
    return saltKey;
}

CryptoPP::SecByteBlock cryptography::getKey(){
    return privKey;
}

CryptoPP::SecByteBlock cryptography::generateSalt(int saltLength){
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock salt(saltLength);
    prng.GenerateBlock(salt, saltLength);

    return salt;
}

CryptoPP::SecByteBlock cryptography::generateKey(std::string password, int derivedKeyLenght, int iterations){
    CryptoPP::SecByteBlock derivedKey(derivedKeyLenght);
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;

    pbkdf.DeriveKey(derivedKey,
    derivedKey.size(),
    0,
    reinterpret_cast<const CryptoPP::byte*>(password.data()),
    password.size(),
    reinterpret_cast<const CryptoPP::byte*>(saltKey.data()),
    saltKey.size(),
    iterations
    );

    return derivedKey;
}

std::string cryptography::encodedHex(CryptoPP::SecByteBlock key){
    std::string hexKey;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexKey));
    encoder.Put(key.data(), key.size());
    encoder.MessageEnd();

    return hexKey;
}

//

std::string cryptography::encrypt(const std::string& plaintext) const {
    std::string ciphertext;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(privKey, privKey.size(), saltKey);
        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::StringSink(ciphertext)
            )
        );
    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Encryption error: " << ex.what() << std::endl;
    }

    return ciphertext;
}

std::string cryptography::decrypt(const std::string& ciphertext) const {
    std::string plaintext;
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(privKey, privKey.size(), saltKey);
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::StringSink(plaintext)
            )
        );
    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
    }
    return plaintext;
}