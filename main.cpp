
#include "source/Crypto.h"

int main(){
    std::string password = "your_password";
    cryptography crypto(10000, 32, 32, &password);

    std::cout << "Salt: " << crypto.encodedHex(crypto.getSalt()) << std::endl;
    std::cout << "Key: " << crypto.encodedHex(crypto.getKey()) << std::endl;
    
    std::string plaintext = "Hello world! This is a test!";
    std::cout << "Plaintext: " << plaintext << std::endl;

    std::string ciphertext = crypto.encrypt(plaintext);
    std::cout << "Ciphertext: " << ciphertext << std::endl;

    std::string decryptedText = crypto.decrypt(ciphertext);
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;

}