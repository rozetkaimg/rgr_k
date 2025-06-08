#ifndef ROT13_XOR_CIPHER_HPP
#define ROT13_XOR_CIPHER_HPP

#include <string>
#include <vector>

struct EncodedResult {
    bool success;
    std::string error_message;
    std::vector<unsigned char> binary_data;
};

struct DecodedResult {
    bool success;
    std::string error_message;
    std::string text;
};

struct FileOperationResult {
    bool success;
    std::string message;
};

EncodedResult encodeTextRot13Xor(const std::string& text);
DecodedResult decodeTextRot13Xor(const std::vector<unsigned char>& data);

FileOperationResult encodeFileRot13Xor(const std::string& inputFilePath, const std::string& outputFilePath);
FileOperationResult decodeFileRot13Xor(const std::string& inputFilePath, const std::string& outputFilePath);

#endif // ROT13_XOR_CIPHER_HPP