#include "gost_bridge.h"
#include "gost.hpp"
#include <cstring>
#include <string>

// Helper function to duplicate a C++ string to a C-style string
char* duplicate_string(const std::string& s) {
    char* cstr = new char[s.length() + 1];
    std::strcpy(cstr, s.c_str());
    return cstr;
}

extern "C" {

DLL_EXPORT GostEncryptedTextResultC encryptTextGOST_C(const char* plaintext,
                                                        const char* key_hex,
                                                        const char* iv_hex) {
    std::string iv_hex_str = (iv_hex) ? iv_hex : "";
    GostEncryptedTextResult result = encryptTextGOST(plaintext, key_hex, iv_hex_str);
    GostEncryptedTextResultC c_result;
    c_result.success = result.success;
    c_result.iv_hex = result.success ? duplicate_string(result.iv_hex) : nullptr;
    c_result.ciphertext_hex = result.success ? duplicate_string(result.ciphertext_hex) : nullptr;
    c_result.error_message = !result.success ? duplicate_string(result.error_message) : nullptr;
    return c_result;
}

DLL_EXPORT GostDecryptedTextResultC decryptTextGOST_C(const char* iv_hex,
                                                        const char* ciphertext_hex,
                                                        const char* key_hex) {
    GostDecryptedTextResult result = decryptTextGOST(iv_hex, ciphertext_hex, key_hex);
    GostDecryptedTextResultC c_result;
    c_result.success = result.success;
    c_result.plaintext = result.success ? duplicate_string(result.plaintext) : nullptr;
    c_result.error_message = !result.success ? duplicate_string(result.error_message) : nullptr;
    return c_result;
}

DLL_EXPORT GostFileOperationResultC encryptFileGOST_C(const char* inputFilePath,
                                                        const char* outputFilePath,
                                                        const char* key_hex,
                                                        const char* initial_iv_hex) {
    std::string initial_iv_hex_str = (initial_iv_hex) ? initial_iv_hex : "";
    GostFileOperationResult result = encryptFileGOST(inputFilePath, outputFilePath, key_hex, initial_iv_hex_str);
    GostFileOperationResultC c_result;
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    c_result.used_iv_hex = result.success ? duplicate_string(result.used_iv_hex) : nullptr;
    return c_result;
}

DLL_EXPORT GostFileOperationResultC decryptFileGOST_C(const char* inputFilePath,
                                                        const char* outputFilePath,
                                                        const char* key_hex) {
    GostFileOperationResult result = decryptFileGOST(inputFilePath, outputFilePath, key_hex);
    GostFileOperationResultC c_result;
    c_result.success = result.success;
    c_result.message = duplicate_string(result.message);
    c_result.used_iv_hex = result.success ? duplicate_string(result.used_iv_hex) : nullptr;
    return c_result;
}


DLL_EXPORT void free_gost_string_C(char* str) {
    delete[] str;
}

} // extern "C"
