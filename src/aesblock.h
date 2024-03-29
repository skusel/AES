#ifndef SKUSEL_AES_BLOCK_H
#define SKUSEL_AES_BLOCK_H

#include "skusel/aes.h"
#include "aeskeysched.h"

namespace skusel
{
  class AESBlock
  {
    public:
      AESBlock(AES::Padding padding, const AESKeySchedule& keySchedule, const uint8_t* data, 
               unsigned dataLen, bool lastBlock);

      static constexpr inline unsigned sizeInBits() {return BLOCK_SIZE_BITS;}
      static constexpr inline unsigned sizeInBytes() {return BLOCK_SIZE_BYTES;}
      
      const uint8_t* encrypt();
      std::pair<const uint8_t*, int> decrypt();

    private:
      void pad();
      unsigned removePadding();

      uint8_t gfmult(uint8_t a, uint8_t b);

      void byteSub();
      void shiftRow();
      void mixCol();
      void invByteSub();
      void invShiftRow();
      void invMixCol();
      void addRoundKey(unsigned round);

      static constexpr const unsigned BLOCK_SIZE_BITS = 128;
      static constexpr const unsigned BLOCK_SIZE_BYTES = BLOCK_SIZE_BITS / 8;
      static constexpr const unsigned WORD_SIZE_BYTES = BLOCK_SIZE_BYTES / 4;

      AES::Padding          m_padding;
      const AESKeySchedule& m_keySchedule;
      const uint8_t*        m_data;
      unsigned              m_dataLen;
      bool                  m_lastBlock;
      uint8_t               m_state[BLOCK_SIZE_BYTES] = {};
  };
}

#endif // SKUSEL_AES_BLOCK_H
