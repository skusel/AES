#ifndef LSKUSE_AES_BLOCK_H
#define LSKUSE_AES_BLOCK_H

#include "lskuse/aes.h"
#include "aeskeysched.h"

namespace lskuse
{
  class AESBlock
  {
    public:
      AESBlock(AES::Padding padding, const std::string& data, const AESKeySchedule& keySchedule);

      static constexpr inline unsigned sizeInBits() {return BLOCK_SIZE_BITS;}
      static constexpr inline unsigned sizeInBytes() {return BLOCK_SIZE_BYTES;}
      
      std::string encrypt();
      std::string decrypt();

    private:
      std::string pad(const std::string& plaintext);
      std::string unpad(const std::string& paddedPlaintext);

      void byteSub();
      void shiftRow();
      void mixCol();
      void invByteSub();
      void invShiftRow();
      void invMixCol();
      void addRoundKey();

      static constexpr const unsigned BLOCK_SIZE_BITS = 128;
      static constexpr const unsigned BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 8;
      static constexpr const unsigned STATE_SIZE = BLOCK_SIZE_BYTES + 1;

      AES::Padding   m_padding;
      std::string    m_data;
      char           m_state[STATE_SIZE] = {};
      AESKeySchedule m_keySchedule;
  };
}

#endif // LSKUSE_AES_BLOCK_H
