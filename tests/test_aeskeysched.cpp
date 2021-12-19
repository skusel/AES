#include "aeskeysched.h"

#include <cstring>

#include <gtest/gtest.h>

namespace lskuse
{
  namespace AESKeyScheduleTest
  {
    TEST(AESKeyScheduleTest, test128KeySchedule)
    {
      char key[17];
      key[0] = 0x2b;
      key[1] = 0x7e;
      key[2] = 0x15;
      key[3] = 0x16;
      key[4] = 0x28;
      key[5] = 0xae;
      key[6] = 0xd2;
      key[7] = 0xa6;
      key[8] = 0xab;
      key[9] = 0xf7;
      key[10] = 0x15;
      key[11] = 0x88;
      key[12] = 0x09;
      key[13] = 0xcf;
      key[14] = 0x4f;
      key[15] = 0x3c;
      key[16] = '\0';

      AESKeySchedule keySched(AES::KeyLen::LEN_128, key);

      // 0th round key should be the same as the original key
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(0), key, 16));
     
      // 1st round key to compare
      key[0] = 0xa0;
      key[1] = 0xfa;
      key[2] = 0xfe;
      key[3] = 0x17;
      key[4] = 0x88;
      key[5] = 0x54;
      key[6] = 0x2c;
      key[7] = 0xb1;
      key[8] = 0x23;
      key[9] = 0xa3;
      key[10] = 0x39;
      key[11] = 0x39;
      key[12] = 0x2a;
      key[13] = 0x6c;
      key[14] = 0x76;
      key[15] = 0x05;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(1), key, 16));

      // 2nd round key to compare
      key[0] = 0xf2;
      key[1] = 0xc2;
      key[2] = 0x95;
      key[3] = 0xf2;
      key[4] = 0x7a;
      key[5] = 0x96;
      key[6] = 0xb9;
      key[7] = 0x43;
      key[8] = 0x59;
      key[9] = 0x35;
      key[10] = 0x80;
      key[11] = 0x7a;
      key[12] = 0x73;
      key[13] = 0x59;
      key[14] = 0xf6;
      key[15] = 0x7f;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(2), key, 16));

      // 3rd round key to compare
      key[0] = 0x3d;
      key[1] = 0x80;
      key[2] = 0x47;
      key[3] = 0x7d;
      key[4] = 0x47;
      key[5] = 0x16;
      key[6] = 0xfe;
      key[7] = 0x3e;
      key[8] = 0x1e;
      key[9] = 0x23;
      key[10] = 0x7e;
      key[11] = 0x44;
      key[12] = 0x6d;
      key[13] = 0x7a;
      key[14] = 0x88;
      key[15] = 0x3b;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(3), key, 16));

      // 4th round key to compare
      key[0] = 0xef;
      key[1] = 0x44;
      key[2] = 0xa5;
      key[3] = 0x41;
      key[4] = 0xa8;
      key[5] = 0x52;
      key[6] = 0x5b;
      key[7] = 0x7f;
      key[8] = 0xb6;
      key[9] = 0x71;
      key[10] = 0x25;
      key[11] = 0x3b;
      key[12] = 0xdb;
      key[13] = 0x0b;
      key[14] = 0xad;
      key[15] = 0x00;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(4), key, 16));

      // 5th round key to compare
      key[0] = 0xd4;
      key[1] = 0xd1;
      key[2] = 0xc6;
      key[3] = 0xf8;
      key[4] = 0x7c;
      key[5] = 0x83;
      key[6] = 0x9d;
      key[7] = 0x87;
      key[8] = 0xca;
      key[9] = 0xf2;
      key[10] = 0xb8;
      key[11] = 0xbc;
      key[12] = 0x11;
      key[13] = 0xf9;
      key[14] = 0x15;
      key[15] = 0xbc;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(5), key, 16));

      // 6th round key to compare
      key[0] = 0x6d;
      key[1] = 0x88;
      key[2] = 0xa3;
      key[3] = 0x7a;
      key[4] = 0x11;
      key[5] = 0x0b;
      key[6] = 0x3e;
      key[7] = 0xfd;
      key[8] = 0xdb;
      key[9] = 0xf9;
      key[10] = 0x86;
      key[11] = 0x41;
      key[12] = 0xca;
      key[13] = 0x00;
      key[14] = 0x93;
      key[15] = 0xfd;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(6), key, 16));

      // 7th round key to compare
      key[0] = 0x4e;
      key[1] = 0x54;
      key[2] = 0xf7;
      key[3] = 0x0e;
      key[4] = 0x5f;
      key[5] = 0x5f;
      key[6] = 0xc9;
      key[7] = 0xf3;
      key[8] = 0x84;
      key[9] = 0xa6;
      key[10] = 0x4f;
      key[11] = 0xb2;
      key[12] = 0x4e;
      key[13] = 0xa6;
      key[14] = 0xdc;
      key[15] = 0x4f;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(7), key, 16));

      // 8th round key to compare
      key[0] = 0xea;
      key[1] = 0xd2;
      key[2] = 0x73;
      key[3] = 0x21;
      key[4] = 0xb5;
      key[5] = 0x8d;
      key[6] = 0xba;
      key[7] = 0xd2;
      key[8] = 0x31;
      key[9] = 0x2b;
      key[10] = 0xf5;
      key[11] = 0x60;
      key[12] = 0x7f;
      key[13] = 0x8d;
      key[14] = 0x29;
      key[15] = 0x2f;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(8), key, 16));

      // 9th round key to compare
      key[0] = 0xac;
      key[1] = 0x77;
      key[2] = 0x66;
      key[3] = 0xf3;
      key[4] = 0x19;
      key[5] = 0xfa;
      key[6] = 0xdc;
      key[7] = 0x21;
      key[8] = 0x28;
      key[9] = 0xd1;
      key[10] = 0x29;
      key[11] = 0x41;
      key[12] = 0x57;
      key[13] = 0x5c;
      key[14] = 0x00;
      key[15] = 0x6e;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(9), key, 16));

      // 10th round key to compare
      key[0] = 0xd0;
      key[1] = 0x14;
      key[2] = 0xf9;
      key[3] = 0xa8;
      key[4] = 0xc9;
      key[5] = 0xee;
      key[6] = 0x25;
      key[7] = 0x89;
      key[8] = 0xe1;
      key[9] = 0x3f;
      key[10] = 0x0c;
      key[11] = 0xc8;
      key[12] = 0xb6;
      key[13] = 0x63;
      key[14] = 0x0c;
      key[15] = 0xa6;
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(10), key, 16));
    }
  }
}
