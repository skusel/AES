#ifndef LSKUSE_AES_H
#define LSKUSE_AES_H

#include <filesystem>
#include <string>

namespace lskuse
{
  class AES
  {
    public:
      struct Status
      {
        bool        m_success = true;
        std::string m_message = "Operation successful";
      };

      enum class KeyLen
      {
        LEN_128,
        LEN_192,
        LEN_256
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

      AES(Mode mode, KeyLen keyLen, Padding padding);

      static Status encrypt(Mode mode, KeyLen keyLen, Padding padding, 
                            const std::filesystem::path& plaintextFile, const std::string& key, 
                            const std::filesystem::path& ciphertextFile);
      static Status decrypt(Mode mode, KeyLen keyLen, Padding padding, 
                            const std::filesystem::path& ciphertextFile, const std::string& key, 
                            const std::filesystem::path& plaintextFile);

      Status encrypt(const std::filesystem::path& plaintextFile, const std::string& key, 
                     const std::filesystem::path& ciphertextFile);
      Status decrypt(const std::filesystem::path& ciphertextFile, const std::string& key, 
                     const std::filesystem::path& plaintextFile);

    private:
      Mode    m_mode;
      KeyLen  m_keyLen;
      Padding m_padding;
      
      static constexpr const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  };
}

#endif // LSKUSE_AES_H
