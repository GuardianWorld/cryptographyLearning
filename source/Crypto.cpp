#include "Crypto.h"

cryptography::cryptography(int iter, std::string* password):
saltKey(generateSalt(S256)),
privKey(generateKey(*password, S256, iter)){
    iterations = iter;
    std::fill(password->begin(), password->end(), 0);
    std::string passwordHash = generateHash(privKey);
    saveHashAndSalt(defaultFile, passwordHash);
}
cryptography::cryptography(): saltKey(32),privKey(32){}

bool cryptography::login(int iter, const std::string& keyFile, std::string* password){
    iterations = iter;
    CryptoPP::SecByteBlock passwordHash = this->retrieveHashAndSalt(keyFile);
    privKey.Assign(generateKey(*password, S256, iterations));
    std::fill(password->begin(), password->end(), 0);
    std::string passwordHashStr(reinterpret_cast<const char*>(passwordHash.data()), passwordHash.size());
    if(generateHash(privKey).compare(passwordHashStr) == 0){
        return true;
    }
    return false;
}

std::string cryptography::generateHash(const CryptoPP::SecByteBlock& value)
{
    std::string hash;

    // Create a SHA256 hash object
    CryptoPP::SHA256 hashFunction;

    // Calculate the hash of the value
    hashFunction.Update(value.BytePtr(), value.size());
    hash.resize(hashFunction.DigestSize());
    hashFunction.Final(reinterpret_cast<CryptoPP::byte*>(&hash[0]));

    //std::cout << "Hash:" << encodedHex(hash) << std::endl;;

    return hash;
}

void cryptography::saveHashAndSalt(const std::string& filename, std::string hashedSafe)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }
    try
    {
        CryptoPP::FileSink fileSink(file);

        // Write the salt and encrypted key to the file
        fileSink.Put(saltKey, saltKey.size());
        fileSink.Put((const unsigned char*)hashedSafe.c_str(), hashedSafe.size());
        file.close();
        std::cout << "Data saved to file: " << filename << std::endl;
    }
    catch (const CryptoPP::Exception& ex)
    {
        std::cerr << "Failed to save data to file: " << ex.what() << std::endl;
    }
}

CryptoPP::SecByteBlock cryptography::retrieveHashAndSalt(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    CryptoPP::SecByteBlock storedKey;
    if (!file)
    {
        std::cerr << "Failed to open file for reading: " << filename << std::endl;
        return storedKey;
    }
    try
    {
        std::vector<CryptoPP::byte> storedKeyVector;
        CryptoPP::FileSource fs(filename.c_str(),false);
        fs.Attach(new CryptoPP::ArraySink(saltKey.begin(), saltKey.size()));
        fs.PumpAll();
        fs.Attach(new CryptoPP::VectorSink(storedKeyVector));
        fs.PumpAll();

        storedKey.Assign(storedKeyVector.data(), storedKeyVector.size());
        std::cout << "Data read from file: " << filename << std::endl;
    }
    catch (const CryptoPP::Exception& ex)
    {
        std::cerr << "Failed to read data from file: " << ex.what() << std::endl;
    }
    return storedKey;
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

std::string cryptography::encodedHex(std::string key){
    std::string hexKey;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexKey));
    encoder.Put((const CryptoPP::byte*) key.data(), key.size());
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

void cryptography::encryptFile(const std::string& inputFile, const std::string& outputFile) const {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(privKey, privKey.size(), saltKey);
        CryptoPP::FileSource(inputFile.c_str(), true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::FileSink(outputFile.c_str())
            )
        );
    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Encryption error: " << ex.what() << std::endl;
    }
}

void cryptography::decryptFile(const std::string& inputFile, const std::string& outputFile) const {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(privKey, privKey.size(), saltKey);

        CryptoPP::FileSource(inputFile.c_str(), true,
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::FileSink(outputFile.c_str())
            )
        );
    } catch (const CryptoPP::Exception& ex) {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
    }
}