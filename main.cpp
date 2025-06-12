#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <iomanip>

// --- Платформо-зависимые заголовоки для динамической загрузки ---
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// --- Подключаем C-совместимые заголовки от наших библиотек ---
#include "gost/gost_bridge.h"
#include "morse/morse_bridge.h"
#include "rot13/rot13_bridge.h"

void displayMenu() {
    std::cout << "\n--- Меню Инструмента Шифрования ---\n"
              << "Выберите алгоритм:\n"
              << "1. ГОСТ (CBC с PKCS7)\n"
              << "2. Морзе (универсальный бинарный)\n"
              << "3. ROT13 + XOR\n"
              << "4. Выход\n"
              << "Введите ваш выбор: ";
}

void printHelp() {
    std::cout << "Использование: ./cipher_tool [опции]\n\n"
              << "Если опции не указаны, будет показано интерактивное меню.\n\n"
              << "Опции:\n"
              << "  --cipher <name>      Указать шифр: 'gost', 'morse', 'rot13'. (Обязательно для работы с флагами)\n"
              << "  -e, --encrypt        Зашифровать входные данные.\n"
              << "  -d, --decrypt        Расшифровать входные данные.\n"
              << "  --generate-key       Сгенерировать ключ ГОСТ и вывести его.\n"
              << "  --text <string>      Текстовая строка для обработки.\n"
              << "  --input <path>       Путь к входному файлу.\n"
              << "  --output <path>      Путь к выходному файту.\n"
              << "  --key <hex_string>   Ключ для ГОСТ (64 hex-символа). Необязателен при шифровании (будет сгенерирован).\n"
              << "  --iv <hex_string>    Вектор инициализации для ГОСТ (16 hex-символов). Можно опустить при шифровании для генерации случайного.\n"
              << "  -h, --help           Показать это справочное сообщение.\n\n"
              << "Примеры:\n"
              << "  ./cipher_tool --cipher gost --generate-key\n"
              << "  ./cipher_tool --cipher gost -e --text \"привет\"\n"
              << "  ./cipher_tool --cipher gost -d --text <hex-шифротекст> --key <64-hex-ключа> --iv <16-hex-iv>\n"
              << "  ./cipher_tool --cipher morse -e --text \"hello\"\n"
              << "  ./cipher_tool --cipher morse -d --text <hex-представление-морзе>\n"
              << "  ./cipher_tool --cipher rot13 -e --input message.txt --output message.enc\n";
}


struct GostFuncs {
    using EncryptTextFunc = GostEncryptedTextResultC (*)(const char*, const char*, const char*);
    using DecryptTextFunc = GostDecryptedTextResultC (*)(const char*, const char*, const char*);
    using EncryptFileFunc = GostFileOperationResultC (*)(const char*, const char*, const char*, const char*);
    using DecryptFileFunc = GostFileOperationResultC (*)(const char*, const char*, const char*);
    using GenerateKeyFunc = GostKeyGenResultC (*)();
    using FreeEncResFunc = void (*)(GostEncryptedTextResultC*);
    using FreeDecResFunc = void (*)(GostDecryptedTextResultC*);
    using FreeFileResFunc = void (*)(GostFileOperationResultC*);
    using FreeKeyResFunc = void(*)(GostKeyGenResultC*);


    EncryptTextFunc encryptText;
    DecryptTextFunc decryptText;
    EncryptFileFunc encryptFile;
    DecryptFileFunc decryptFile;
    GenerateKeyFunc generateKey;
    FreeEncResFunc freeEncResult;
    FreeDecResFunc freeDecResult;
    FreeFileResFunc freeFileResult;
    FreeKeyResFunc freeKeyResult;
};

struct MorseFuncs {
    using EncodeTextFunc = MorseEncodedResultC (*)(const char*);
    using DecodeTextFunc = MorseDecodedResultC (*)(const unsigned char*, size_t);
    using EncodeFileFunc = MorseFileOperationResultC (*)(const char*, const char*);
    using DecodeFileFunc = MorseFileOperationResultC (*)(const char*, const char*);
    using FreeEncResFunc = void (*)(MorseEncodedResultC*);
    using FreeDecResFunc = void (*)(MorseDecodedResultC*);
    using FreeFileResFunc = void (*)(MorseFileOperationResultC*);

    EncodeTextFunc encodeText;
    DecodeTextFunc decodeText;
    EncodeFileFunc encodeFile;
    DecodeFileFunc decodeFile;
    FreeEncResFunc freeEncResult;
    FreeDecResFunc freeDecResult;
    FreeFileResFunc freeFileResult;
};

struct Rot13Funcs {
    using EncodeTextFunc = EncodedResultC (*)(const char*);
    using DecodeTextFunc = DecodedResultC (*)(const unsigned char*, size_t);
    using EncodeFileFunc = FileOperationResultC (*)(const char*, const char*);
    using DecodeFileFunc = FileOperationResultC (*)(const char*, const char*);
    using FreeEncResFunc = void (*)(EncodedResultC*);
    using FreeDecResFunc = void (*)(DecodedResultC*);
    using FreeFileResFunc = void (*)(FileOperationResultC*);

    EncodeTextFunc encodeText;
    DecodeTextFunc decodeText;
    EncodeFileFunc encodeFile;
    DecodeFileFunc decodeFile;
    FreeEncResFunc freeEncResult;
    FreeDecResFunc freeDecResult;
    FreeFileResFunc freeFileResult;
};

// --- Глобальный менеджер загруженных библиотек ---

#ifdef _WIN32
using LibraryHandle = HMODULE;
#else
using LibraryHandle = void*;
#endif

struct Library {
    LibraryHandle handle = nullptr;
    union {
        GostFuncs gost;
        MorseFuncs morse;
        Rot13Funcs rot13;
    } funcs;

    ~Library() {
        if (handle) {
            #ifdef _WIN32
            FreeLibrary(handle);
            #else
            dlclose(handle);
            #endif
        }
    }
};

std::map<std::string, std::unique_ptr<Library>> loaded_libraries;

template<typename T>
T load_symbol(LibraryHandle handle, const char* name) {
    #ifdef _WIN32
    return reinterpret_cast<T>(GetProcAddress(handle, name));
    #else
    return reinterpret_cast<T>(dlsym(handle, name));
    #endif
}

bool load_cipher_library(const std::string& cipher_name) {
    if (loaded_libraries.count(cipher_name)) {
        return true;
    }

    std::string lib_path;
    #ifdef _WIN32
    lib_path = cipher_name + "_cipher.dll";
    #else
    // Путь для Linux, предполагающий, что библиотеки лежат рядом
    lib_path = "./lib" + cipher_name + "_cipher.so";
    #endif

    LibraryHandle handle = nullptr;
    #ifdef _WIN32
    handle = LoadLibrary(lib_path.c_str());
    #else
    handle = dlopen(lib_path.c_str(), RTLD_LAZY);
    #endif

    if (!handle) {
        std::cerr << "Ошибка: не удалось загрузить библиотеку: " << lib_path << std::endl;
        #ifndef _WIN32
        if(dlerror() != NULL) std::cerr << "dlopen error: " << dlerror() << std::endl;
        #endif
        return false;
    }

    auto lib = std::make_unique<Library>();
    lib->handle = handle;

    bool success = true;

    if (cipher_name == "gost") {
        lib->funcs.gost = {
            load_symbol<GostFuncs::EncryptTextFunc>(handle, "encryptTextGOST_C"),
            load_symbol<GostFuncs::DecryptTextFunc>(handle, "decryptTextGOST_C"),
            load_symbol<GostFuncs::EncryptFileFunc>(handle, "encryptFileGOST_C"),
            load_symbol<GostFuncs::DecryptFileFunc>(handle, "decryptFileGOST_C"),
            load_symbol<GostFuncs::GenerateKeyFunc>(handle, "generateKeyGOST_C"),
            load_symbol<GostFuncs::FreeEncResFunc>(handle, "free_gost_encrypted_result_C"),
            load_symbol<GostFuncs::FreeDecResFunc>(handle, "free_gost_decrypted_result_C"),
            load_symbol<GostFuncs::FreeFileResFunc>(handle, "free_gost_file_result_C"),
            load_symbol<GostFuncs::FreeKeyResFunc>(handle, "free_gost_key_result_C")
        };
    } else if (cipher_name == "morse") {
        lib->funcs.morse = {
            load_symbol<MorseFuncs::EncodeTextFunc>(handle, "encodeTextToMorse_C"),
            load_symbol<MorseFuncs::DecodeTextFunc>(handle, "decodeTextFromMorse_C"),
            load_symbol<MorseFuncs::EncodeFileFunc>(handle, "encodeFileToMorse_C"),
            load_symbol<MorseFuncs::DecodeFileFunc>(handle, "decodeFileFromMorse_C"),
            load_symbol<MorseFuncs::FreeEncResFunc>(handle, "free_morse_encoded_result_C"),
            load_symbol<MorseFuncs::FreeDecResFunc>(handle, "free_morse_decoded_result_C"),
            load_symbol<MorseFuncs::FreeFileResFunc>(handle, "free_morse_file_result_C")
        };
    } else if (cipher_name == "rot13") {
        lib->funcs.rot13 = {
            load_symbol<Rot13Funcs::EncodeTextFunc>(handle, "encodeTextRot13Xor_C"),
            load_symbol<Rot13Funcs::DecodeTextFunc>(handle, "decodeTextRot13Xor_C"),
            load_symbol<Rot13Funcs::EncodeFileFunc>(handle, "encodeFileRot13Xor_C"),
            load_symbol<Rot13Funcs::DecodeFileFunc>(handle, "decodeFileRot13Xor_C"),
            load_symbol<Rot13Funcs::FreeEncResFunc>(handle, "free_rot13_encoded_result_C"),
            load_symbol<Rot13Funcs::FreeDecResFunc>(handle, "free_rot13_decoded_result_C"),
            load_symbol<Rot13Funcs::FreeFileResFunc>(handle, "free_rot13_file_result_C")
        };
    } else {
        success = false;
    }

    if (!success) return false;

    loaded_libraries[cipher_name] = std::move(lib);
    return true;
}

// --- Вспомогательные функции и меню ---

void displayMenu();
void handleGostMenu();
void handleMorseMenu();
void handleRot13Menu();

std::string to_hex_string(const unsigned char* data, size_t size) {
    if (!data) return "";
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
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



int main(int argc, char* argv[]) {
    #ifdef _WIN32
        setlocale(LC_ALL, "Russian");
    #endif

    if (argc > 1) {
        std::string cipher, text, inputFile, outputFile, key, iv;
        bool encrypt = false, decrypt = false, generateKey = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") {
                printHelp(); return 0;
            } else if (arg == "--cipher") {
                cipher = (i + 1 < argc) ? argv[++i] : "";
            } else if (arg == "-e" || arg == "--encrypt") {
                encrypt = true;
            } else if (arg == "-d" || arg == "--decrypt") {
                decrypt = true;
            } else if (arg == "--generate-key") {
                generateKey = true;
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

        if (cipher.empty() || (encrypt && decrypt) || (generateKey && (encrypt || decrypt))) {
            std::cerr << "Ошибка: Вы должны указать шифр и ровно один режим (--encrypt, --decrypt или --generate-key)." << std::endl;
            printHelp(); return 1;
        }

        if (!load_cipher_library(cipher)) {
            return 1;
        }

        try {
            if (cipher == "gost") {
                auto* funcs = &loaded_libraries.at(cipher)->funcs.gost;

                if (generateKey) {
                    GostKeyGenResultC res = funcs->generateKey();
                    if (res.success) {
                        std::cout << "Сгенерированный ключ (hex): " << res.key_hex << std::endl;
                    } else throw std::runtime_error(res.error_message ? res.error_message : "Unknown error during key generation.");
                    funcs->freeKeyResult(&res);
                    return 0;
                }

                if (encrypt) {
                    if (key.empty()) {
                        GostKeyGenResultC key_res = funcs->generateKey();
                        if (key_res.success) {
                            key = key_res.key_hex;
                             std::cout << "Ключ не указан, сгенерирован новый: " << key << std::endl;
                        } else {
                            std::string err_msg = key_res.error_message ? key_res.error_message : "Unknown error during key generation.";
                            funcs->freeKeyResult(&key_res);
                            throw std::runtime_error("Не удалось сгенерировать ключ: " + err_msg);
                        }
                        funcs->freeKeyResult(&key_res);
                    }
                    if (!text.empty()) {
                        GostEncryptedTextResultC res = funcs->encryptText(text.c_str(), key.c_str(), iv.c_str());
                        if (res.success) {
                            std::cout << "Шифрование успешно.\n" << "IV (hex): " << res.iv_hex << "\n" << "Шифротекст (hex): " << res.ciphertext_hex << std::endl;
                        } else throw std::runtime_error(res.error_message ? res.error_message : "Unknown encryption error.");
                        funcs->freeEncResult(&res);
                    } else if (!inputFile.empty() && !outputFile.empty()) {
                        GostFileOperationResultC res = funcs->encryptFile(inputFile.c_str(), outputFile.c_str(), key.c_str(), iv.c_str());
                        if(res.success) std::cout << res.message << "\n" << "Использованный IV: " << res.used_iv_hex << std::endl;
                        else throw std::runtime_error(res.message ? res.message : "Unknown file encryption error.");
                        funcs->freeFileResult(&res);
                    } else throw std::runtime_error("Для шифрования ГОСТ укажите либо --text, либо --input и --output.");
                } else { // Decrypt
                    if (key.empty()) throw std::runtime_error("Для дешифрования ГОСТ требуется ключ (--key).");
                    if (iv.empty() && !inputFile.empty()) { /* IV is read from file for decryption */ }
                    else if (iv.empty()) throw std::runtime_error("Для дешифрования текста ГОСТ требуется вектор инициализации (--iv).");

                     if (!text.empty()) {
                        GostDecryptedTextResultC res = funcs->decryptText(iv.c_str(), text.c_str(), key.c_str());
                         if (res.success) std::cout << "Дешифрование успешно.\n" << "Открытый текст: " << res.plaintext << std::endl;
                         else throw std::runtime_error(res.error_message ? res.error_message : "Unknown decryption error.");
                         funcs->freeDecResult(&res);
                    } else if (!inputFile.empty() && !outputFile.empty()) {
                         GostFileOperationResultC res = funcs->decryptFile(inputFile.c_str(), outputFile.c_str(), key.c_str());
                         if(res.success) std::cout << res.message << std::endl;
                         else throw std::runtime_error(res.message ? res.message : "Unknown file decryption error.");
                         funcs->freeFileResult(&res);
                    } else throw std::runtime_error("Для дешифрования ГОСТ укажите либо --text (как шифротекст), либо --input и --output.");
                }
            } else if (cipher == "morse") {
                auto* funcs = &loaded_libraries.at(cipher)->funcs.morse;
                if (!text.empty()) {
                    if (encrypt) {
                        MorseEncodedResultC res = funcs->encodeText(text.c_str());
                        if (res.success) std::cout << "Кодирование в Морзе успешно.\n" << "Бинарные данные (hex): " << to_hex_string(res.binary_data, res.data_size) << std::endl;
                        else throw std::runtime_error(res.error_message ? res.error_message : "Unknown Morse encoding error.");
                        funcs->freeEncResult(&res);
                    } else {
                        std::vector<unsigned char> data = from_hex_string(text);
                        MorseDecodedResultC res = funcs->decodeText(data.data(), data.size());
                        if (res.success) std::cout << "Декодирование из Морзе успешно.\n" << "Открытый текст: " << res.plaintext << std::endl;
                        else throw std::runtime_error(res.error_message ? res.error_message : "Unknown Morse decoding error.");
                        funcs->freeDecResult(&res);
                    }
                } else if (!inputFile.empty() && !outputFile.empty()) {
                    MorseFileOperationResultC res = encrypt ? funcs->encodeFile(inputFile.c_str(), outputFile.c_str()) : funcs->decodeFile(inputFile.c_str(), outputFile.c_str());
                    if(res.success) std::cout << res.message << std::endl;
                    else throw std::runtime_error(res.message ? res.message : "Unknown Morse file operation error.");
                    funcs->freeFileResult(&res);
                } else throw std::runtime_error("Для операций с Морзе укажите либо --text, либо --input и --output.");
            } else if (cipher == "rot13") {
                auto* funcs = &loaded_libraries.at(cipher)->funcs.rot13;
                if (!text.empty()) {
                    if (encrypt) {
                        EncodedResultC res = funcs->encodeText(text.c_str());
                        if(res.success) std::cout << "Кодирование ROT13+XOR успешно.\n" << "Бинарные данные (hex): " << to_hex_string(res.binary_data, res.data_size) << std::endl;
                        else throw std::runtime_error(res.error_message ? res.error_message : "Unknown ROT13 encoding error.");
                        funcs->freeEncResult(&res);
                    } else {
                        std::vector<unsigned char> data = from_hex_string(text);
                        DecodedResultC res = funcs->decodeText(data.data(), data.size());
                        if(res.success) std::cout << "Декодирование ROT13+XOR успешно.\n" << "Открытый текст: " << res.text << std::endl;
                        else throw std::runtime_error(res.error_message ? res.error_message : "Unknown ROT13 decoding error.");
                        funcs->freeDecResult(&res);
                    }
                } else if (!inputFile.empty() && !outputFile.empty()) {
                    FileOperationResultC res = encrypt ? funcs->encodeFile(inputFile.c_str(), outputFile.c_str()) : funcs->decodeFile(inputFile.c_str(), outputFile.c_str());
                    if(res.success) std::cout << res.message << std::endl;
                    else throw std::runtime_error(res.message ? res.message : "Unknown ROT13 file operation error.");
                    funcs->freeFileResult(&res);
                } else throw std::runtime_error("Для операций с ROT13+XOR укажите либо --text, либо --input и --output.");
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
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1: handleGostMenu(); break;
            case 2: handleMorseMenu(); break;
            case 3: handleRot13Menu(); break;
            case 4: std::cout << "Выход." << std::endl; break;
            default: std::cout << "Неверный выбор, попробуйте снова." << std::endl;
        }
        if (choice != 4) {
            std::cout << "\nНажмите Enter, чтобы продолжить...";
            std::cin.get();
        }
    } while (choice != 4);

    return 0;
}

void handleGostMenu() {
    if (!load_cipher_library("gost")) return;
    auto* funcs = &loaded_libraries.at("gost")->funcs.gost;

    int choice;
    std::cout << "\n-- Меню ГОСТ --\n1. Зашифровать текст\n2. Расшифровать текст\n3. Зашифровать файл\n4. Расшифровать файл\n5. Сгенерировать ключ\nВведите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::string text, key_hex, iv_hex, inputFile, outputFile;

    try {
        if (choice == 2 || choice == 4) { // Decryption requires key
             std::cout << "Введите ключ (64 hex-символа): ";
             std::getline(std::cin, key_hex);
             if(key_hex.empty()){
                std::cout << "Дешифрование требует ключ." << std::endl;
                return;
             }
        } else if (choice == 1 || choice == 3) { // Encryption can generate key
             std::cout << "Введите ключ (64 hex-символа) или оставьте пустым для генерации: ";
             std::getline(std::cin, key_hex);
        }

        switch (choice) {
            case 1:
            case 3: {
                if (key_hex.empty()) {
                    GostKeyGenResultC key_res = funcs->generateKey();
                     if (key_res.success) {
                        key_hex = key_res.key_hex;
                         std::cout << "-> Сгенерирован новый ключ: " << key_hex << std::endl;
                    } else {
                        std::cerr << "Ошибка генерации ключа: " << (key_res.error_message ? key_res.error_message : "Неизвестная ошибка") << std::endl;
                        funcs->freeKeyResult(&key_res);
                        return;
                    }
                    funcs->freeKeyResult(&key_res);
                }

                if (choice == 1) {
                    std::cout << "Введите текст для шифрования: ";
                    std::getline(std::cin, text);
                    std::cout << "Введите IV (16 hex-символов) или оставьте пустым для случайного: ";
                    std::getline(std::cin, iv_hex);
                    GostEncryptedTextResultC res = funcs->encryptText(text.c_str(), key_hex.c_str(), iv_hex.c_str());
                    if (res.success) {
                        std::cout << "\nШифрование успешно!\n" << "IV: " << res.iv_hex << "\n" << "Шифротекст: " << res.ciphertext_hex << std::endl;
                    } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                    funcs->freeEncResult(&res);
                } else { // choice == 3
                     std::cout << "Введите путь к входному файлу: ";
                     std::getline(std::cin, inputFile);
                     std::cout << "Введите путь к выходному файлу: ";
                     std::getline(std::cin, outputFile);
                     std::cout << "Введите IV (16 hex-символов) или оставьте пустым для случайного: ";
                     std::getline(std::cin, iv_hex);
                    GostFileOperationResultC res = funcs->encryptFile(inputFile.c_str(), outputFile.c_str(), key_hex.c_str(), iv_hex.c_str());
                    std::cout << "\n" << res.message << std::endl;
                    if(res.success) std::cout << "Использованный IV: " << res.used_iv_hex << std::endl;
                    funcs->freeFileResult(&res);
                }
                break;
            }
            case 2: { // Расшифровать текст
                std::cout << "Введите IV (16 hex-символов): ";
                std::getline(std::cin, iv_hex);
                std::cout << "Введите шифротекст (hex): ";
                std::getline(std::cin, text);
                GostDecryptedTextResultC res = funcs->decryptText(iv_hex.c_str(), text.c_str(), key_hex.c_str());
                 if (res.success) {
                    std::cout << "\nДешифрование успешно!\n" << "Открытый текст: " << res.plaintext << std::endl;
                } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                funcs->freeDecResult(&res);
                break;
            }
            case 4: { // Расшифровать файл
                 std::cout << "Введите путь к входному файлу: ";
                 std::getline(std::cin, inputFile);
                 std::cout << "Введите путь к выходному файлу: ";
                 std::getline(std::cin, outputFile);
                GostFileOperationResultC res = funcs->decryptFile(inputFile.c_str(), outputFile.c_str(), key_hex.c_str());
                std::cout << "\n" << res.message << std::endl;
                if(res.success) std::cout << "IV, прочитанный из файла: " << res.used_iv_hex << std::endl;
                funcs->freeFileResult(&res);
                break;
            }
            case 5: { // Сгенерировать ключ
                GostKeyGenResultC res = funcs->generateKey();
                if (res.success) {
                    std::cout << "\nСгенерированный ключ (hex): " << res.key_hex << std::endl;
                } else {
                    std::cerr << "Ошибка генерации ключа: " << (res.error_message ? res.error_message : "Неизвестная ошибка") << std::endl;
                }
                funcs->freeKeyResult(&res);
                break;
            }
            default: std::cout << "Неверный выбор." << std::endl;
        }
    } catch(const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}

void handleMorseMenu() {
    if (!load_cipher_library("morse")) return;
    auto* funcs = &loaded_libraries.at("morse")->funcs.morse;

    int choice;
    std::cout << "\n-- Меню Морзе --\n1. Кодировать текст\n2. Декодировать текст\n3. Кодировать файл\n4. Декодировать файл\nВведите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try {
        switch (choice) {
            case 1: {
                std::cout << "Введите текст для кодирования: ";
                std::string plaintext;
                std::getline(std::cin, plaintext);
                MorseEncodedResultC res = funcs->encodeText(plaintext.c_str());
                if (res.success) {
                    std::cout << "\nКодирование успешно!\n" << "Результат (hex): " << to_hex_string(res.binary_data, res.data_size) << std::endl;
                } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                funcs->freeEncResult(&res);
                break;
            }
            case 2: {
                std::cout << "Введите данные для декодирования (hex): ";
                std::string hex_data;
                std::getline(std::cin, hex_data);
                std::vector<unsigned char> data = from_hex_string(hex_data);
                MorseDecodedResultC res = funcs->decodeText(data.data(), data.size());
                 if (res.success) {
                    std::cout << "\nДекодирование успешно!\n" << "Открытый текст: " << res.plaintext << std::endl;
                } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                funcs->freeDecResult(&res);
                break;
            }
            case 3:
            case 4: {
                std::cout << "Введите путь к входному файлу: ";
                std::string inputFile;
                std::getline(std::cin, inputFile);
                std::cout << "Введите путь к выходному файлу: ";
                std::string outputFile;
                std::getline(std::cin, outputFile);
                MorseFileOperationResultC res = (choice == 3) ? funcs->encodeFile(inputFile.c_str(), outputFile.c_str()) : funcs->decodeFile(inputFile.c_str(), outputFile.c_str());
                std::cout << "\n" << res.message << std::endl;
                funcs->freeFileResult(&res);
                break;
            }
            default: std::cout << "Неверный выбор." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}

void handleRot13Menu() {
    if (!load_cipher_library("rot13")) return;
    auto* funcs = &loaded_libraries.at("rot13")->funcs.rot13;

    int choice;
    std::cout << "\n-- Меню ROT13 + XOR --\n1. Кодировать текст\n2. Декодировать текст\n3. Кодировать файл\n4. Декодировать файл\nВведите ваш выбор: ";
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

     try {
        switch (choice) {
            case 1: {
                std::cout << "Введите текст для кодирования: ";
                std::string plaintext;
                std::getline(std::cin, plaintext);
                EncodedResultC res = funcs->encodeText(plaintext.c_str());
                if (res.success) {
                    std::cout << "\nКодирование успешно!\n" << "Результат (hex): " << to_hex_string(res.binary_data, res.data_size) << std::endl;
                } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                funcs->freeEncResult(&res);
                break;
            }
            case 2: {
                std::cout << "Введите данные для декодирования (hex): ";
                std::string hex_data;
                std::getline(std::cin, hex_data);
                std::vector<unsigned char> data = from_hex_string(hex_data);
                DecodedResultC res = funcs->decodeText(data.data(), data.size());
                 if (res.success) {
                    std::cout << "\nДекодирование успешно!\n" << "Открытый текст: " << res.text << std::endl;
                } else std::cerr << "Ошибка: " << res.error_message << std::endl;
                funcs->freeDecResult(&res);
                break;
            }
            case 3:
            case 4: {
                std::cout << "Введите путь к входному файлу: ";
                std::string inputFile;
                std::getline(std::cin, inputFile);
                std::cout << "Введите путь к выходному файлу: ";
                std::string outputFile;
                std::getline(std::cin, outputFile);
                FileOperationResultC res = (choice == 3) ? funcs->encodeFile(inputFile.c_str(), outputFile.c_str()) : funcs->decodeFile(inputFile.c_str(), outputFile.c_str());
                std::cout << "\n" << res.message << std::endl;
                funcs->freeFileResult(&res);
                break;
            }
            default: std::cout << "Неверный выбор." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
    }
}
