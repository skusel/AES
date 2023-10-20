#ifndef SKUSEL_AES_H
#define SKUSEL_AES_H

#include <filesystem>
#include <string>

namespace skusel
{
  class AES
  {
    public:
      struct Status
      {
        bool        m_success = true;
        std::string m_message = "Operation successful";
      };

      enum class Mode
      {
        ECB,
        // TODO: add other modes here
      };

      enum class Padding
      {
        PKCS7,
        // TODO: add other padding types here
      };

      AES(Mode mode, Padding padding);

      static Status encrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& plaintextFile, std::string_view key, 
                            const std::filesystem::path& ciphertextFile);
      static Status encrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& plaintextFile, 
                            const std::array<char, 16>& key, 
                            const std::filesystem::path& ciphertextFile);
      static Status encrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& plaintextFile, 
                            const std::array<char, 24>& key, 
                            const std::filesystem::path& ciphertextFile);
      static Status encrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& plaintextFile, 
                            const std::array<char, 32>& key, 
                            const std::filesystem::path& ciphertextFile);
      
      static Status decrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& ciphertextFile, std::string_view key, 
                            const std::filesystem::path& plaintextFile);
      static Status decrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& ciphertextFile,
                            const std::array<char, 16>& key, 
                            const std::filesystem::path& plaintextFile);
      static Status decrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& ciphertextFile,
                            const std::array<char, 24>& key, 
                            const std::filesystem::path& plaintextFile);
      static Status decrypt(Mode mode, Padding padding, 
                            const std::filesystem::path& ciphertextFile,
                            const std::array<char, 32>& key, 
                            const std::filesystem::path& plaintextFile);
      
      Status encrypt(const std::filesystem::path& plaintextFile, std::string_view key, 
                     const std::filesystem::path& ciphertextFile);
      Status encrypt(const std::filesystem::path& plaintextFile, 
                     const std::array<char, 16>& key, 
                     const std::filesystem::path& ciphertextFile);
      Status encrypt(const std::filesystem::path& plaintextFile, 
                     const std::array<char, 24>& key, 
                     const std::filesystem::path& ciphertextFile);
      Status encrypt(const std::filesystem::path& plaintextFile, 
                     const std::array<char, 32>& key, 
                     const std::filesystem::path& ciphertextFile);

      Status decrypt(const std::filesystem::path& ciphertextFile, std::string_view key, 
                     const std::filesystem::path& plaintextFile);
      Status decrypt(const std::filesystem::path& ciphertextFile,
                     const std::array<char, 16>& key, 
                     const std::filesystem::path& plaintextFile);
      Status decrypt(const std::filesystem::path& ciphertextFile,
                     const std::array<char, 24>& key, 
                     const std::filesystem::path& plaintextFile);
      Status decrypt(const std::filesystem::path& ciphertextFile,
                     const std::array<char, 32>& key, 
                     const std::filesystem::path& plaintextFile);

    private:
      Status checkKeyLength(std::string_view key);
      template<typename KeyType>
      Status runEncrypt(const std::filesystem::path& plaintextFile, KeyType genericKey,
                        const std::filesystem::path& ciphertextFile);
      template<typename KeyType>
      Status runDecrypt(const std::filesystem::path& ciphertextFile, KeyType genericKey,
                        const std::filesystem::path& plaintextFile);

      Mode    m_mode;
      Padding m_padding;
      
      static constexpr const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  };
}

#endif // SKUSEL_AES_H
