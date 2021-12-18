#ifndef LSKUSE_KEY_SCHEDULE_H
#define LSKUSE_KEY_SCHEDULE_H

#include "lskuse/aes.h"

#include <vector>

namespace lskuse
{
  class KeySchedule
  {
    public:
      KeySchedule(AES::KeyLen keyLen, const std::string& key);

      char* getRoundKey(unsigned round);

    private:
      void computeKeySchedule();
      void rotWord();
      void subWord();
      void rcon();

      AES::KeyLen        m_keyLen;
      std::string        m_key;
      std::vector<char*> m_keySchedule;

      static constexpr const uint8_t RCON[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
  };
}

#endif // LSKUSE_KEY_SCHEDULE_H
