#include "rot13_bridge.h"
#include "rot13_bitwise.h"
#include <cstring>
#include <vector>

// Вспомогательная функция для копирования std::string в C-строку (char*)
static char* duplicate_string(const std::string& s) {
    if (s.empty()) return nullptr;
    char* cstr = new char[s.length() + 1];
    std::strcpy(cstr, s.c_str());
    return cstr;
}

extern "C" {

DLL_EXPORT EncodedResultC encodeTextRot13Xor_C(const char* text) {
    EncodedResult result = encodeTextRot13Xor(std::string(text));
    EncodedResultC c_result = {};
    c_result.success = result.success;
    c_result.error_message = duplicate_string(result.error_message);
    if (result.success) {
        c_result.data_size = result.binary_data.size();
        c_result.binary_data = new unsigned char[c_result.data_size];
        std::memcpy(c_result.binary_data, result.binary_data.data(), c_result.data_size);
    }
    return c_result;
}

DLL_EXPORT DecodedResultC decodeTextRot13Xor_C(const unsigned char* data, size_t data_size) {
    std::vector<unsigned char> data_vec(data, data + data_size);
    DecodedResult result = decodeTextRot13Xor(data_vec);
    DecodedResultC c_result = {};
    c_result.success = result.success;
    c_result.error_message = duplicate_string(result.error_message);
    if (result.success) {
        c_result.text = duplicate_string(result.text);
    }
    return c_result;
}

DLL_EXPORT FileOperationResultC encodeFileRot13Xor_C(const char* inputFilePath, const char* outputFilePath) {
    FileOperationResult result = encodeFileRot13Xor(inputFilePath, outputFilePath);
    FileOperationResultC c_result = {};
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    return c_result;
}

DLL_EXPORT FileOperationResultC decodeFileRot13Xor_C(const char* inputFilePath, const char* outputFilePath) {
    FileOperationResult result = decodeFileRot13Xor(inputFilePath, outputFilePath);
    FileOperationResultC c_result = {};
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    return c_result;
}

// Реализация функций для освобождения памяти
DLL_EXPORT void free_rot13_encoded_result_C(EncodedResultC* result) {
    if (result) {
        delete[] result->error_message;
        delete[] result->binary_data;
    }
}

DLL_EXPORT void free_rot13_decoded_result_C(DecodedResultC* result) {
    if (result) {
        delete[] result->error_message;
        delete[] result->text;
    }
}

DLL_EXPORT void free_rot13_file_result_C(FileOperationResultC* result) {
    if (result) {
        delete[] result->message;
    }
}

} // extern "C"
