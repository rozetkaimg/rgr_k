#include "gost.hpp"
#include <iostream>
#include <fstream>
#include <vector>

void generateRandomBytes(std::vector<unsigned char> &buffer, size_t length);
void printTextResults(const std::string& operation, const GostEncryptedTextResult& result) {
    std::cout << "--- " << operation << " ---" << std::endl;
    if (result.success) {
        std::cout << "IV (hex): " << result.iv_hex << std::endl;
        std::cout << "Ciphertext (hex): " << result.ciphertext_hex << std::endl;
    } else {
        std::cout << "Error: " << result.error_message << std::endl;
    }
    std::cout << std::endl;
}
void printTextResults(const std::string& operation, const GostDecryptedTextResult& result) {
    std::cout << "--- " << operation << " ---" << std::endl;
    if (result.success) {
        std::cout << "Plaintext: " << result.plaintext << std::endl;
    } else {
        std::cout << "Error: " << result.error_message << std::endl;
    }
    std::cout << std::endl;
}
void printFileResults(const std::string& operation, const GostFileOperationResult& result) {
    std::cout << "--- " << operation << " ---" << std::endl;
    if (result.success) {
        std::cout << "Success: " << result.message << std::endl;
        if (!result.used_iv_hex.empty()) {
            std::cout << "IV used (hex): " << result.used_iv_hex << std::endl;
        }
    } else {
        std::cout << "Error: " << result.message << std::endl;
    }
    std::cout << std::endl;
}


int main() {
    // --- 1. Пример шифрования и дешифрования текста ---
    std::cout << "========================================" << std::endl;
    std::cout << "       Text Encryption/Decryption       " << std::endl;
    std::cout << "========================================" << std::endl;

    // Генерируем случайный ключ для примера
    std::vector<unsigned char> key_bytes(GOST_KEY_SIZE_BYTES);
    // Предполагается, что generateRandomBytes реализована и работает
    // generateRandomBytes(key_bytes, GOST_KEY_SIZE_BYTES); 
    // Для воспроизводимости примера используем статический ключ:
    std::string key_hex = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF";
    
    std::string original_text = "Это тестовое сообщение для шифрования ГОСТ.";
    
    std::cout << "Original Text: " << original_text << std::endl;
    std::cout << "Key (hex): " << key_hex << std::endl << std::endl;

    // Шифруем текст (IV будет сгенерирован автоматически)
    GostEncryptedTextResult enc_result = encryptTextGOST(original_text, key_hex);
    printTextResults("Text Encryption", enc_result);

    // Дешифруем текст, используя IV и шифротекст из предыдущего шага
    if (enc_result.success) {
        GostDecryptedTextResult dec_result = decryptTextGOST(enc_result.iv_hex, enc_result.ciphertext_hex, key_hex);
        printTextResults("Text Decryption", dec_result);
    }
    
    // --- 2. Пример шифрования и дешифрования файла ---
    std::cout << "========================================" << std::endl;
    std::cout << "        File Encryption/Decryption        " << std::endl;
    std::cout << "========================================" << std::endl;

    const std::string inputFile = "plaintext.txt";
    const std::string encryptedFile = "encrypted.dat";
    const std::string decryptedFile = "decrypted.txt";

    // Создаем исходный файл для шифрования
    std::cout << "Creating dummy file '" << inputFile << "'..." << std::endl;
    std::ofstream out(inputFile);
    out << "Это содержимое тестового файла.\n";
    out << "Он будет зашифрован, а затем расшифрован.\n";
    out.close();
    std::cout << "File created." << std::endl << std::endl;

    // Шифруем файл
    GostFileOperationResult enc_file_result = encryptFileGOST(inputFile, encryptedFile, key_hex);
    printFileResults("File Encryption", enc_file_result);

    // Дешифруем файл
    if (enc_file_result.success) {
        GostFileOperationResult dec_file_result = decryptFileGOST(encryptedFile, decryptedFile, key_hex);
        printFileResults("File Decryption", dec_file_result);

        // (Опционально) Проверяем содержимое расшифрованного файла
        std::ifstream ifs(decryptedFile);
        std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
        std::cout << "--- Decrypted File Content ---" << std::endl;
        std::cout << content << std::endl;
    }


    return 0;
}