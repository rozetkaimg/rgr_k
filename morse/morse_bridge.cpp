#include "morse_bridge.h"
#include "morse.h"
#include <cstring>

// Вспомогательная функция для копирования std::string в C-строку (char*)
// Память выделяется через new[], чтобы можно было освободить через delete[]
static char* duplicate_string(const std::string& s) {
    char* cstr = new char[s.length() + 1];
    std::strcpy(cstr, s.c_str());
    return cstr;
}


extern "C" {

DLL_EXPORT MorseEncodedResultC encodeTextToMorse_C(const char* plaintext) {
    MorseEncodedResult result = encodeTextToMorse(std::string(plaintext));
    MorseEncodedResultC c_result = {};
    
    c_result.success = result.success;
    if (result.success) {
        c_result.data_size = result.binary_data.size();
        c_result.binary_data = new unsigned char[c_result.data_size];
        std::memcpy(c_result.binary_data, result.binary_data.data(), c_result.data_size);
    } else {
        c_result.error_message = duplicate_string(result.error_message);
    }
    return c_result;
}

DLL_EXPORT MorseDecodedResultC decodeTextFromMorse_C(const unsigned char* binary_data, size_t data_size) {
    std::vector<unsigned char> data_vec(binary_data, binary_data + data_size);
    MorseDecodedResult result = decodeTextFromMorse(data_vec);
    MorseDecodedResultC c_result = {};

    c_result.success = result.success;
    if (result.success) {
        c_result.plaintext = duplicate_string(result.plaintext);
    } else {
        c_result.error_message = duplicate_string(result.error_message);
    }
    return c_result;
}

DLL_EXPORT MorseFileOperationResultC encodeFileToMorse_C(const char* inputFilePath, const char* outputFilePath) {
    MorseFileOperationResult result = encodeFileToMorse(inputFilePath, outputFilePath);
    MorseFileOperationResultC c_result = {};
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    return c_result;
}

DLL_EXPORT MorseFileOperationResultC decodeFileFromMorse_C(const char* inputFilePath, const char* outputFilePath) {
    MorseFileOperationResult result = decodeFileFromMorse(inputFilePath, outputFilePath);
    MorseFileOperationResultC c_result = {};
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    return c_result;
}

// Реализация функций для освобождения памяти
DLL_EXPORT void free_morse_encoded_result_C(MorseEncodedResultC* result) {
    if (result) {
        delete[] result->binary_data;
        delete[] result->error_message;
    }
}

DLL_EXPORT void free_morse_decoded_result_C(MorseDecodedResultC* result) {
    if (result) {
        delete[] result->plaintext;
        delete[] result->error_message;
    }
}

DLL_EXPORT void free_morse_file_result_C(MorseFileOperationResultC* result) {
    if (result) {
        delete[] result->message;
    }
}

} // extern "C"
