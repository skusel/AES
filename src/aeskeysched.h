#ifndef SKUSEL_KEY_SCHEDULE_H
#define SKUSEL_KEY_SCHEDULE_H

#include "skusel/aes.h"

#include <vector>

namespace skusel
{
  class AESKeySchedule
  {
    public:
      AESKeySchedule(unsigned keyLenBytes, const char* key);
      ~AESKeySchedule();

      unsigned getNumRounds() const;
      uint8_t* getRoundKey(unsigned round) const;

    private:
      void computeKeySchedule(const char* key);
      void compute128KeySchedule(const char* key);
      void compute192KeySchedule(const char* key);
      void compute256KeySchedule(const char* key);
      void rotWord(uint8_t* word);
      void subWord(uint8_t* word);
      void rcon(uint8_t* word, unsigned round);

      enum class KeyLen
      {
        LEN_128,
        LEN_192,
        LEN_256
      };

      static constexpr const unsigned WORD_LEN = 4;
      static constexpr const unsigned ROUND_KEY_LEN = 16;
      static constexpr const unsigned LEN_128_IN_BYTES = 16;
      static constexpr const unsigned LEN_192_IN_BYTES = 24;
      static constexpr const unsigned LEN_256_IN_BYTES = 32;
      static constexpr const unsigned LEN_128_WORD_ARRAY_SIZE = 44 * WORD_LEN;
      static constexpr const unsigned LEN_192_WORD_ARRAY_SIZE = 54 * WORD_LEN; // really only needs to be 52
      static constexpr const unsigned LEN_256_WORD_ARRAY_SIZE = 64 * WORD_LEN; // really only needs to be 60
      static constexpr const unsigned LEN_128_TRANSFORMATIONS = LEN_128_WORD_ARRAY_SIZE / LEN_128_IN_BYTES - 1;
      static constexpr const unsigned LEN_192_TRANSFORMATIONS = LEN_192_WORD_ARRAY_SIZE / LEN_192_IN_BYTES - 1;
      static constexpr const unsigned LEN_256_TRANSFORMATIONS = LEN_256_WORD_ARRAY_SIZE / LEN_256_IN_BYTES - 1;

      KeyLen                m_keyLen;
      std::vector<uint8_t*> m_keySchedule;

      /************************************************************************
       * RCON obtained from... 
       * https://en.wikipedia.org/wiki/AES_key_schedule
       ***********************************************************************/
      static constexpr const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
  };
}

#endif // SKUSEL_KEY_SCHEDULE_H
