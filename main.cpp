#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <limits>
#include "gost/gost.hpp"
#include "morse/morse.h"
#include "rot13/rot13_bitwise.h"
#include <sstream>
#include <iomanip>


void displayMenu();
void handleGostMenu();
void handleMorseMenu();
void handleRot13Menu();


std::string to_hex_string(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : data) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}

std::vector<unsigned char> from_hex_string(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex-строка должна иметь четное количество символов.");
    }
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception& e) {
            throw std::invalid_argument("Недопустимый символ в hex-строке: " + byteString);
        }
    }
    return bytes;
}

void printHelp() {
    std::cout << "Использование: ./cipher_tool [опции]\n\n"
              << "Если опции не указаны, будет показано интерактивное меню.\n\n"
              << "Опции:\n"
              << "  --cipher <name>      Указать шифр: 'gost', 'morse', 'rot13'. (Обязательно для работы с флагами)\n"
              << "  -e, --encrypt        Зашифровать входные данные.\n"
              << "  -d, --decrypt        Расшифровать входные данные.\n"
              << "  --text <string>      Текстовая строка для обработки.\n"
              << "  --input <path>       Путь к входному файлу.\n"
              << "  --output <path>      Путь к выходному файлу.\n"
              << "  --key <hex_string>   Ключ для ГОСТ (64 hex-символа).\n"
              << "  --iv <hex_string>    Вектор инициализации для ГОСТ (16 hex-символов). Можно опустить при шифровании для генерации случайного.\n"
              << "  -h, --help           Показать это справочное сообщение.\n\n"
              << "Примеры:\n"
              << "  ./cipher_tool --cipher gost -e --text \"привет\" --key <64-hex-ключа>\n"
              << "  ./cipher_tool --cipher morse -e --text \"hello\"\n"
              << "  ./cipher_tool --cipher morse -d --text <hex-представление-морзе>\n"
              << "  ./cipher_tool --cipher rot13 -e --input message.txt --output message.enc\n";
}


int main(int argc, char* argv[]) {
    #ifdef _WIN32
        setlocale(LC_ALL, "Russian");
    #endif

    if (argc > 1) {
    
        std::string cipher, text, inputFile, outputFile, key, iv;
        bool encrypt = false, decrypt = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") {
                printHelp();
                return 0;
            } else if (arg == "--cipher") {
                cipher = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "-e" || arg == "--encrypt") {
                encrypt = true;
            } else if (arg == "-d" || arg == "--decrypt") {
                decrypt = true;
            } else if (arg == "--text") {
                text = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "--input") {
                inputFile = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "--output") {
                outputFile = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "--key") {
                key = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "--iv") {
                iv = (i + 1 < argc) ? argv[++i] : "";
            }
        }

        if (cipher.empty() || (encrypt == decrypt)) {
            std::cerr << "Ошибка: Вы должны указать шифр и ровно один режим (-e или -d)." << std::endl;
            printHelp();
            return 1;
        }

        try {
            if (cipher == "gost") {
                if (key.empty()) throw std::runtime_error("ГОСТ требует указания ключа (--key).");
                if (encrypt) {
                    if (!text.empty()) {
                        GostEncryptedTextResult res = encryptTextGOST(text, key, iv);
                        if (res.success) {
                            std::cout << "Шифрование успешно.\n"
                                      << "IV (hex): " << res.iv_hex << "\n"
                                      << "Шифротекст (hex): " << res.ciphertext_hex << std::endl;
                        } else {
                            throw std::runtime_error(res.error_message);
                        }
                    } else if (!inputFile.empty() && !outputFile.empty()) {
                        GostFileOperationResult res = encryptFileGOST(inputFile, outputFile, key, iv);
                        if(res.success) {
                            std::cout << res.message << "\n" << "Использованный IV: " << res.used_iv_hex << std::endl;
                        } else {
                            throw std::runtime_error(res.message);
                        }
                    } else {
                         throw std::runtime_error("Для шифрования ГОСТ укажите либо --text, либо --input и --output.");
                    }
                } else { // Decrypt
                    if (iv.empty()) throw std::runtime_error("Для дешифрования ГОСТ требуется вектор инициализации (--iv).");
                     if (!text.empty()) {
                        GostDecryptedTextResult res = decryptTextGOST(iv, text, key);
                         if (res.success) {
                            std::cout << "Дешифрование успешно.\n"
                                      << "Открытый текст: " << res.plaintext << std::endl;
                        } else {
                            throw std::runtime_error(res.error_message);
                        }
                    } else if (!inputFile.empty() && !outputFile.empty()) {
                         GostFileOperationResult res = decryptFileGOST(inputFile, outputFile, key);
                        if(res.success) {
                           std::cout << res.message << std::endl;
                        } else {
                           throw std::runtime_error(res.message);
                        }
                    } else {
                        throw std::runtime_error("Для дешифрования ГОСТ укажите либо --text (как шифротекст), либо --input и --output.");
                    }
                }
            } else if (cipher == "morse") {
                 if (!text.empty()) {
                    if (encrypt) {
                        MorseEncodedResult res = encodeTextToMorse(text);
                        if (res.success) {
                            std::cout << "Кодирование в Морзе успешно.\n"
                                      << "Бинарные данные (hex): " << to_hex_string(res.binary_data) << std::endl;
                        } else {
                             throw std::runtime_error(res.error_message);
                        }
                    } else { // decrypt
                        MorseDecodedResult res = decodeTextFromMorse(from_hex_string(text));
                        if (res.success) {
                             std::cout << "Декодирование из Морзе успешно.\n"
                                      << "Открытый текст: " << res.plaintext << std::endl;
                        } else {
                            throw std::runtime_error(res.error_message);
                        }
                    }
                 } else if (!inputFile.empty() && !outputFile.empty()) {
                    MorseFileOperationResult res = encrypt ? encodeFileToMorse(inputFile, outputFile) : decodeFileFromMorse(inputFile, outputFile);
                     if(res.success) {
                         std::cout << res.message << std::endl;
                     } else {
                         throw std::runtime_error(res.message);
                     }
                 } else {
                    throw std::runtime_error("Для операций с Морзе укажите либо --text, либо --input и --output.");
                 }
            } else if (cipher == "rot13") {
                 if (!text.empty()) {
                    if (encrypt) {
                        EncodedResult res = encodeTextRot13Xor(text);
                        if(res.success) {
                             std::cout << "Кодирование ROT13+XOR успешно.\n"
                                      << "Бинарные данные (hex): " << to_hex_string(res.binary_data) << std::endl;
                        } else {
                             throw std::runtime_error(res.error_message);
                        }
                    } else { // decrypt
                        DecodedResult res = decodeTextRot13Xor(from_hex_string(text));
                        if(res.success) {
                            std::cout << "Декодирование ROT13+XOR успешно.\n"
                                      << "Открытый текст: " << res.text << std::endl;
                        } else {
                            throw std::runtime_error(res.error_message);
                        }
                    }
                 } else if (!inputFile.empty() && !outputFile.empty()) {
                    FileOperationResult res = encrypt ? encodeFileRot13Xor(inputFile, outputFile) : decodeFileRot13Xor(inputFile, outputFile);
                     if(res.success) {
                         std::cout << res.message << std::endl;
                     } else {
                         throw std::runtime_error(res.message);
                     }
                 } else {
                    throw std::runtime_error("Для операций с ROT13+XOR укажите либо --text, либо --input и --output.");
                 }
            } else {
                throw std::runtime_error("Указан неверный шифр.");
            }
        } catch (const std::exception& e) {
            std::cerr << "Произошла ошибка: " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }

    // --- ИНТЕРАКТИВНОЕ МЕНЮ ---
    int choice;
    do {
        displayMenu();
        std::cin >> choice;
        // Очистка буфера ввода после считывания числа
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                handleGostMenu();
                break;
            case 2:
                handleMorseMenu();
                break;
            case 3:
                handleRot13Menu();
                break;
            case 4:
                std::cout << "Выход." << std::endl;
                break;
            default:
                std::cout << "Неверный выбор, попробуйте снова." << std::endl;
        }
        if (choice != 4) {
            std::cout << "\nНажмите Enter, чтобы продолжить...";
            std::cin.get();
        }
    } while (choice != 4);

    return 0;
}

// --- Реализация функций меню ---

void displayMenu() {
    std::cout << "\n--- Меню Инструмента Шифрования ---\n"
              << "Выберите алгоритм:\n"
              << "1. ГОСТ (CBC с PKCS7)\n"
              << "2. Морзе (универсальный бинарный)\n"
              << "3. ROT13 + XOR\n"
              << "4. Выход\n"
              << "Введите ваш выбор: ";
}

void handleGostMenu() {
    int choice;
    std::string text, key_hex, iv_hex, inputFile, outputFile;

    std::cout << "\n-- Меню ГОСТ --\n"
              << "1. Зашифровать текст\n"
              << "2. Расшифровать текст\n"
              << "3. Зашифровать файл\n"
              << "4. Расшифровать файл\n"
              << "Введите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try {
        if (choice == 1 || choice == 2 || choice == 3 || choice == 4) {
             std::cout << "Введите ключ (64 hex-символа): ";
             std::getline(std::cin, key_hex);
        }

        switch (choice) {
            case 1: // Зашифровать текст
                std::cout << "Введите текст для шифрования: ";
                std::getline(std::cin, text);
                std::cout << "Введите IV (16 hex-символов) или оставьте пустым для случайного: ";
                std::getline(std::cin, iv_hex);
                {
                    GostEncryptedTextResult res = encryptTextGOST(text, key_hex, iv_hex);
                    if (res.success) {
                        std::cout << "\nШифрование успешно!\n"
                                  << "IV: " << res.iv_hex << "\n"
                                  << "Шифротекст: " << res.ciphertext_hex << std::endl;
                    } else {
                        std::cerr << "Ошибка: " << res.error_message << std::endl;
                    }
                }
                break;
            case 2: // Расшифровать текст
                std::cout << "Введите IV (16 hex-символов): ";
                std::getline(std::cin, iv_hex);
                std::cout << "Введите шифротекст (hex): ";
                std::getline(std::cin, text);
                {
                    GostDecryptedTextResult res = decryptTextGOST(iv_hex, text, key_hex);
                     if (res.success) {
                        std::cout << "\nДешифрование успешно!\n"
                                  << "Открытый текст: " << res.plaintext << std::endl;
                    } else {
                        std::cerr << "Ошибка: " << res.error_message << std::endl;
                    }
                }
                break;
            case 3: // Зашифровать файл
                 std::cout << "Введите путь к входному файлу: ";
                 std::getline(std::cin, inputFile);
                 std::cout << "Введите путь к выходному файлу: ";
                 std::getline(std::cin, outputFile);
                 std::cout << "Введите IV (16 hex-символов) или оставьте пустым для случайного: ";
                 std::getline(std::cin, iv_hex);
                {
                    GostFileOperationResult res = encryptFileGOST(inputFile, outputFile, key_hex, iv_hex);
                    std::cout << "\n" << res.message << std::endl;
                    if(res.success) std::cout << "Использованный IV: " << res.used_iv_hex << std::endl;
                }
                break;
            case 4: // Расшифровать файл
                 std::cout << "Введите путь к входному файлу: ";
                 std::getline(std::cin, inputFile);
                 std::cout << "Введите путь к выходному файлу: ";
                 std::getline(std::cin, outputFile);
                {
                    GostFileOperationResult res = decryptFileGOST(inputFile, outputFile, key_hex);
                    std::cout << "\n" << res.message << std::endl;
                    if(res.success) std::cout << "IV, прочитанный из файла: " << res.used_iv_hex << std::endl;
                }
                break;
            default:
                std::cout << "Неверный выбор." << std::endl;
        }
    } catch(const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}


void handleMorseMenu() {
    int choice;
    std::cout << "\n-- Меню Морзе --\n"
              << "1. Кодировать текст\n"
              << "2. Декодировать текст\n"
              << "3. Кодировать файл\n"
              << "4. Декодировать файл\n"
              << "Введите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try {
        switch (choice) {
            case 1: { // Кодировать текст
                std::cout << "Введите текст для кодирования: ";
                std::string plaintext;
                std::getline(std::cin, plaintext);
                MorseEncodedResult res = encodeTextToMorse(plaintext);
                if (res.success) {
                    std::cout << "\nКодирование успешно!\n"
                              << "Результат (hex): " << to_hex_string(res.binary_data) << std::endl;
                } else {
                    std::cerr << "Ошибка: " << res.error_message << std::endl;
                }
                break;
            }
            case 2: { // Декодировать текст
                std::cout << "Введите данные для декодирования (hex): ";
                std::string hex_data;
                std::getline(std::cin, hex_data);
                MorseDecodedResult res = decodeTextFromMorse(from_hex_string(hex_data));
                 if (res.success) {
                    std::cout << "\nДекодирование успешно!\n"
                              << "Открытый текст: " << res.plaintext << std::endl;
                } else {
                    std::cerr << "Ошибка: " << res.error_message << std::endl;
                }
                break;
            }
            case 3:
            case 4: { // Файловые операции
                std::cout << "Введите путь к входному файлу: ";
                std::string inputFile;
                std::getline(std::cin, inputFile);
                std::cout << "Введите путь к выходному файлу: ";
                std::string outputFile;
                std::getline(std::cin, outputFile);
                MorseFileOperationResult res = (choice == 3) ? encodeFileToMorse(inputFile, outputFile) : decodeFileFromMorse(inputFile, outputFile);
                std::cout << "\n" << res.message << std::endl;
                break;
            }
            default:
                std::cout << "Неверный выбор." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}


void handleRot13Menu() {
    int choice;
    std::cout << "\n-- Меню ROT13 + XOR --\n"
              << "1. Кодировать текст\n"
              << "2. Декодировать текст\n"
              << "3. Кодировать файл\n"
              << "4. Декодировать файл\n"
              << "Введите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

     try {
        switch (choice) {
            case 1: { // Кодировать текст
                std::cout << "Введите текст для кодирования: ";
                std::string plaintext;
                std::getline(std::cin, plaintext);
                EncodedResult res = encodeTextRot13Xor(plaintext);
                if (res.success) {
                    std::cout << "\nКодирование успешно!\n"
                              << "Результат (hex): " << to_hex_string(res.binary_data) << std::endl;
                } else {
                    std::cerr << "Ошибка: " << res.error_message << std::endl;
                }
                break;
            }
            case 2: { // Декодировать текст
                std::cout << "Введите данные для декодирования (hex): ";
                std::string hex_data;
                std::getline(std::cin, hex_data);
                DecodedResult res = decodeTextRot13Xor(from_hex_string(hex_data));
                 if (res.success) {
                    std::cout << "\nДекодирование успешно!\n"
                              << "Открытый текст: " << res.text << std::endl;
                } else {
                    std::cerr << "Ошибка: " << res.error_message << std::endl;
                }
                break;
            }
            case 3:
            case 4: { // Файловые операции
                std::cout << "Введите путь к входному файлу: ";
                std::string inputFile;
                std::getline(std::cin, inputFile);
                std::cout << "Введите путь к выходному файлу: ";
                std::string outputFile;
                std::getline(std::cin, outputFile);
                FileOperationResult res = (choice == 3) ? encodeFileRot13Xor(inputFile, outputFile) : decodeFileRot13Xor(inputFile, outputFile);
                std::cout << "\n" << res.message << std::endl;
                break;
            }
            default:
                std::cout << "Неверный выбор." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}