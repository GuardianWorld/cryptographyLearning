
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

int main(){
    cryptography* crypto;

    if(!doesFileExist("keys.bin")){
        std::string password = "your_password";
        std::string TFA = "universe";
        std::cout << "Digit a password!\n>> ";
        std::cin >> password;
        std::cout << "Do you wish to set Two Factor Auth Key?\n>> ";
        std::string confirmation;
        std::cin >> confirmation;
        if(confirmation.compare("yes") == 0 || 
        confirmation.compare("Yes") == 0 || 
        confirmation.compare("Y") == 0|| 
        confirmation.compare("YES") == 0 ||
        confirmation.compare("y") == 0){
            std::cout << "Digit a TFA key!\n>> ";
            std::cin >> TFA;
        }
        crypto = new cryptography(600000,&password,&TFA);
        std::cout << "Keep keys.bin saved AND your password!!\n";
    }
    else{
        crypto = new cryptography();
        while(true){
            std::string password = "your_password";
            std::string TFA = "universe";
            std::string TFAL = "";
            std::cout << "Digit your password!\n>> ";
            std::cin >> password;
            getchar();
            std::cout << "If you have a TFA key, digit it, otherwise, press enter.\n>> ";
            std::getline(std::cin, TFAL);
            if(!TFAL.empty()){
                TFA = TFAL;
            }
            if(crypto->login(600000, "keys.bin", &password, &TFA)){
                break;
            }
            else{
                std::cerr << "Error! Digit a valid Password and TFA Key\n";
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
        std::string file;
        std::string path;
        size_t slashIndex;

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
                slashIndex = inputFile.find_last_of("/\\");
                if (slashIndex != std::string::npos) {
                    file = inputFile.substr(slashIndex + 1);
                    path = inputFile.substr(0, slashIndex + 1);
                }
                else{
                    file = inputFile;
                }

                encryptedFile = path + "enc_" + file;
                std::cout << encryptedFile << std::endl;
                crypto->encryptFile(inputFile, encryptedFile);
                std::cout << "File encrypted." << std::endl;
                break;
            case 3:

                // Decrypt the file
                std::cout << "Choose a file to be decrypted.\n >";
                std::cin >> encryptedFile;
                encryptedFile = removeQuotes(encryptedFile);
                slashIndex = encryptedFile.find_last_of("/\\");
                if (slashIndex != std::string::npos) {
                    file = encryptedFile.substr(slashIndex + 1);
                    path = encryptedFile.substr(0, slashIndex + 1);
                }
                else{
                    file = encryptedFile;
                }

                if (file.substr(0, 4) == "enc_")
                {
                    std::string tempFileSTR = file;
                    tempFileSTR.erase(0, 4);
                    decryptedFile = path + "dec_" + tempFileSTR;
                    
                }
                else{
                    decryptedFile = path + "dec_" + file;
                }
                crypto->decryptFile(encryptedFile, decryptedFile);
                std::cout << "File decrypted." << std::endl;
                break;
        }    
    }

    return 0;

}