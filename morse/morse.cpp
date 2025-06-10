#include "morse.h"
#include <fstream>
#include <map>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstring>

static const std::map<unsigned char, std::string> nibble_to_morse_map = {
    {0x0, "."},    {0x1, "-"},    {0x2, ".."},   {0x3, ".-"},
    {0x4, "-."},   {0x5, "--"},   {0x6, "..."},  {0x7, "..-"},
    {0x8, ".-."},  {0x9, ".--"},  {0xA, "-.."},  {0xB, "-.-"},
    {0xC, "--."},  {0xD, "---"},  {0xE, "...."}, {0xF, "...-"}
};

// Обратная карта для декодирования, инициализируется один раз
static std::map<std::string, unsigned char> morse_to_nibble_map;
static bool is_reverse_map_initialized = false;

static void initialize_reverse_map() {
    if (!is_reverse_map_initialized) {
        for (const auto& pair : nibble_to_morse_map) {
            morse_to_nibble_map[pair.second] = pair.first;
        }
        is_reverse_map_initialized = true;
    }
}


// --- Битовые представления элементов ---
const std::string MORSE_DOT_BITS = "1";
const std::string MORSE_DASH_BITS = "111";
const std::string INTRA_ELEMENT_GAP = "0";
const std::string BYTE_PART_GAP = "000";
const std::string INTER_BYTE_GAP = "0000000";

// Вспомогательная функция: преобразовать строку Морзе (напр. ".-") в битовую строку ("10111")
std::string morse_to_bit_string(const std::string& morse_code) {
    std::string bits;
    for (size_t i = 0; i < morse_code.length(); ++i) {
        bits += (morse_code[i] == '.') ? MORSE_DOT_BITS : MORSE_DASH_BITS;
        if (i < morse_code.length() - 1) {
            bits += INTRA_ELEMENT_GAP;
        }
    }
    return bits;
}


MorseEncodedResult encodeTextToMorse(const std::string &plaintext) {
    MorseEncodedResult result;
    std::string final_bit_string;

    // 1. Кодируем каждый БАЙТ текста
    for (size_t i = 0; i < plaintext.length(); ++i) {
        unsigned char byte = plaintext[i];
        
        // Делим байт на старший и младший нибблы
        unsigned char high_nibble = (byte >> 4) & 0x0F;
        unsigned char low_nibble = byte & 0x0F;

        // Кодируем оба ниббла
        final_bit_string += morse_to_bit_string(nibble_to_morse_map.at(high_nibble));
        final_bit_string += BYTE_PART_GAP; // Пауза между частями байта
        final_bit_string += morse_to_bit_string(nibble_to_morse_map.at(low_nibble));

        if (i < plaintext.length() - 1) {
            final_bit_string += INTER_BYTE_GAP; // Пауза между байтами
        }
    }

    // 2. Упаковываем битовую строку в вектор байтов с метаданными
    std::vector<unsigned char> packed_bytes;
    uint64_t total_bits = final_bit_string.length();
    
    // Записываем 8 байт метаданных (длина в битах)
    packed_bytes.resize(sizeof(total_bits));
    std::memcpy(packed_bytes.data(), &total_bits, sizeof(total_bits));

    unsigned char current_byte = 0;
    int bit_count = 0;
    for (char bit : final_bit_string) {
        current_byte = (current_byte << 1) | (bit - '0');
        bit_count++;
        if (bit_count == 8) {
            packed_bytes.push_back(current_byte);
            bit_count = 0;
        }
    }
    if (bit_count > 0) {
        current_byte <<= (8 - bit_count); // Добиваем нулями до полного байта
        packed_bytes.push_back(current_byte);
    }

    result.binary_data = packed_bytes;
    result.success = true;
    return result;
}


MorseDecodedResult decodeTextFromMorse(const std::vector<unsigned char> &binary_data) {
    MorseDecodedResult result;
    initialize_reverse_map();

    if (binary_data.size() < sizeof(uint64_t)) {
        return { {}, false, "Invalid data: too short." };
    }

    // 1. Извлекаем метаданные и восстанавливаем битовую строку
    uint64_t total_bits;
    std::memcpy(&total_bits, binary_data.data(), sizeof(total_bits));

    std::string bit_string;
    bit_string.reserve(binary_data.size() * 8);
    for (size_t i = sizeof(total_bits); i < binary_data.size(); ++i) {
        for (int j = 7; j >= 0; --j) {
            bit_string += ((binary_data[i] >> j) & 1) ? '1' : '0';
        }
    }
    if (bit_string.length() > total_bits) {
        bit_string.resize(total_bits);
    }
    
    // 2. Парсим битовую строку, восстанавливая байты
    std::string plaintext_result;
    std::string current_morse_code;
    unsigned char reconstructed_byte = 0;
    bool is_high_nibble = true;

    for (size_t i = 0; i < bit_string.length(); ) {
        // Ищем следующий разделитель (последовательность нулей)
        size_t gap_pos = bit_string.find('0', i);
        if (gap_pos == std::string::npos) { // Дошли до конца
            gap_pos = bit_string.length();
        }

        // Извлекаем код морзе для элемента (точки или тире)
        std::string element_bits = bit_string.substr(i, gap_pos - i);
        if (element_bits == MORSE_DOT_BITS) current_morse_code += '.';
        else if (element_bits == MORSE_DASH_BITS) current_morse_code += '-';

        i = gap_pos;
        
        // Ищем длину паузы (считаем нули)
        size_t zero_count = 0;
        while(i < bit_string.length() && bit_string[i] == '0') {
            zero_count++;
            i++;
        }

        // Если пауза большая, значит, мы закончили собирать код для ниббла
        if (zero_count >= 3 || i >= bit_string.length()) {
            if (morse_to_nibble_map.count(current_morse_code)) {
                unsigned char nibble = morse_to_nibble_map.at(current_morse_code);
                if (is_high_nibble) {
                    reconstructed_byte = (nibble << 4);
                    is_high_nibble = false;
                } else {
                    reconstructed_byte |= nibble;
                    plaintext_result += static_cast<char>(reconstructed_byte);
                    is_high_nibble = true;
                }
            }
            current_morse_code.clear();
        }
    }

    result.plaintext = plaintext_result;
    result.success = true;
    return result;
}


// --- Функции для работы с файлами (остаются без изменений) ---

MorseFileOperationResult encodeFileToMorse(const std::string &inputFilePath, const std::string &outputFilePath) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) return {false, "Error: Cannot open input file."};
    
    std::string content((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    MorseEncodedResult encoded_data = encodeTextToMorse(content);

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) return {false, "Error: Cannot open output file."};

    outputFile.write(reinterpret_cast<const char*>(encoded_data.binary_data.data()), encoded_data.binary_data.size());
    outputFile.close();
    
    return {true, "File successfully encoded to universal binary Morse."};
}

MorseFileOperationResult decodeFileFromMorse(const std::string &inputFilePath, const std::string &outputFilePath) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) return {false, "Error: Cannot open input file."};

    std::vector<unsigned char> content((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    MorseDecodedResult decoded_data = decodeTextFromMorse(content);
    if (!decoded_data.success) return {false, decoded_data.error_message};

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) return {false, "Error: Cannot open output file."};

    outputFile << decoded_data.plaintext;
    outputFile.close();

    return {true, "File successfully decoded from universal binary Morse."};
}
