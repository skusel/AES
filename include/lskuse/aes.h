#ifndef LSKUSE_AES_H
#define LSKUSE_AES_H

#include <string>

namespace lskuse
{
  class AES
  {
    public:
      enum class KeyLen
      {
        LEN_128,
        LEN_192,
        LEN_256
      };

      enum class Mode
      {
        ECB,
        CBC
      };

      enum class Padding
      {
        ZEROS,
        ISO
      };

      AES(Mode mode, KeyLen keyLen, Padding padding);

      static std::string encrypt(const std::string& data, const std::string& key, 
                                 Mode mode, KeyLen keyLen, Padding padding);
      static std::string decrypt(const std::string& data, const std::string& key, 
                                 Mode mode, KeyLen keyLen, Padding padding);

      std::string encrypt(const std::string& data, const std::string& key);
      std::string decrypt(const std::string& data, const std::string& key);

    private:
      KeyLen  m_keyLen;
      Mode    m_mode;
      Padding m_padding;
      
      static constexpr const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
  };
}

#endif // LSKUSE_AES_H
