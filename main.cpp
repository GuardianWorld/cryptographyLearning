
#include "source/Crypto.h"

bool doesFileExist(const std::string& filename){
    std::ifstream file(filename);
    bool isOpen = file.is_open();
    file.close();
    return isOpen;
}

std::string removeQuotes(const std::string& str) {
    std::string result = str;
    result.erase(std::remove(result.begin(), result.end(), '\''), result.end());
    return result;
}

std::string func(std::string input, std::string aux, std::string removal, bool shouldRemove){
    std::string file;
    std::string path;

    size_t slashIndex = input.find_last_of("/\\");
    if (slashIndex != std::string::npos) {
        file = input.substr(slashIndex + 1);
        path = input.substr(0, slashIndex + 1);
    }
    else{
        file = input;
    }
    std::string finalFilePath;

    if(shouldRemove){
        if (file.substr(0, 4) == removal)
                {
                    std::string tempFileSTR = file;
                    tempFileSTR.erase(0, 4);
                    finalFilePath = path + aux + tempFileSTR;
                    
                }
                else{
                    finalFilePath = path + aux + file;
                }
    }
    else{
        finalFilePath = path + aux + file;
    }
    return finalFilePath;
}

int main(){
    cryptography* crypto;

    if(!doesFileExist("keys.bin")){
        std::string password = "universe";
        std::cout << "Digit a password!\n>> ";
        std::cin >> password;
        crypto = new cryptography(600000,&password);
        std::cout << "Keep keys.bin saved AND your password!!\n";
    }
    else{
        crypto = new cryptography();
        while(true){
            std::string password = "universe";
            std::cout << "Digit your password!\n>> ";
            std::getline(std::cin, password);
            if(password.empty()){
                password = "universe";
            }
            if(crypto->login(600000, "keys.bin", &password)){
                break;
            }
            else{
                std::cerr << "Error! Digit a valid Password\n";
            }
        }
    }

    int x = 0;
    while(true){
        std::cout << "Choose the option:\n" << "0) Close\n" << "1) Get Salt and Key\n" << "2) encrypt file.\n" << "3) decript file\n" << std::endl; 
        std::cin >> x;

        std::string inputFile;
        std::string encryptedFile;
        std::string decryptedFile;

        switch (x){
            case 0:
                return 0;
                break;
            case 1:
                std::cout << "Salt: " << crypto->encodedHex(crypto->getSalt()) << std::endl;
                std::cout << "Key: " << crypto->encodedHex(crypto->getKey()) << std::endl;
                break;
            case 2:
                std::cout << "Choose a file to be encrypted.\n >";
                std::cin >> inputFile;
                inputFile = removeQuotes(inputFile);
                encryptedFile = func(inputFile, "enc_", "", false);
                crypto->encryptFile(inputFile, encryptedFile);
                std::cout << "File encrypted." << std::endl;
                break;
            case 3:

                // Decrypt the file
                std::cout << "Choose a file to be decrypted.\n >";
                std::cin >> encryptedFile;
                encryptedFile = removeQuotes(encryptedFile);
                decryptedFile = func(encryptedFile, "dec_", "enc_", true);

                crypto->decryptFile(encryptedFile, decryptedFile);
                std::cout << "File decrypted." << std::endl;
                break;
        }    
    }

    return 0;

}