#include "aeskeysched.h"

#include <cstring>

#include <gtest/gtest.h>

/******************************************************************************
 * Known values taken from...
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf 
 * Appendix A - Key Expansion Examples
 * Pages 27-32
 *****************************************************************************/

namespace lskuse
{
  namespace AESKeyScheduleTest
  {
    TEST(AESKeyScheduleTest, test128KeySchedule)
    {
      char origKey[16];
      origKey[0] = 0x2b;
      origKey[1] = 0x7e;
      origKey[2] = 0x15;
      origKey[3] = 0x16;
      origKey[4] = 0x28; 
      origKey[5] = 0xae; 
      origKey[6] = 0xd2; 
      origKey[7] = 0xa6;
      origKey[8] = 0xab; 
      origKey[9] = 0xf7;
      origKey[10] = 0x15; 
      origKey[11] = 0x88;
      origKey[12] = 0x09; 
      origKey[13] = 0xcf; 
      origKey[14] = 0x4f;
      origKey[15] = 0x3c;

      AESKeySchedule keySched(AES::KeyLen::LEN_128, origKey);

      // 0th round key
      uint8_t key0[16] = {0x2b, 0x7e, 0x15, 0x16,
                          0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88,
                          0x09, 0xcf, 0x4f, 0x3c};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(0), key0, 16));

      // 1st round key
      uint8_t key1[16] = {0xa0, 0xfa, 0xfe, 0x17,
                          0x88, 0x54, 0x2c, 0xb1,
                          0x23, 0xa3, 0x39, 0x39,
                          0x2a, 0x6c, 0x76, 0x05};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(1), key1, 16));

      // 2nd round key
      uint8_t key2[16] = {0xf2, 0xc2, 0x95, 0xf2,
                          0x7a, 0x96, 0xb9, 0x43,
                          0x59, 0x35, 0x80, 0x7a,
                          0x73, 0x59, 0xf6, 0x7f};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(2), key2, 16));

      // 3rd round key
      uint8_t key3[16] = {0x3d, 0x80, 0x47, 0x7d,
                          0x47, 0x16, 0xfe, 0x3e,
                          0x1e, 0x23, 0x7e, 0x44,
                          0x6d, 0x7a, 0x88, 0x3b};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(3), key3, 16));

      // 4th round key
      uint8_t key4[16] = {0xef, 0x44, 0xa5, 0x41,
                          0xa8, 0x52, 0x5b, 0x7f,
                          0xb6, 0x71, 0x25, 0x3b,
                          0xdb, 0x0b, 0xad, 0x00};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(4), key4, 16));

      // 5th round key
      uint8_t key5[16] = {0xd4, 0xd1, 0xc6, 0xf8,
                          0x7c, 0x83, 0x9d, 0x87,
                          0xca, 0xf2, 0xb8, 0xbc,
                          0x11, 0xf9, 0x15, 0xbc};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(5), key5, 16));

      // 6th round key
      uint8_t key6[16] = {0x6d, 0x88, 0xa3, 0x7a,
                          0x11, 0x0b, 0x3e, 0xfd,
                          0xdb, 0xf9, 0x86, 0x41,
                          0xca, 0x00, 0x93, 0xfd};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(6), key6, 16));

      // 7th round key
      uint8_t key7[16] = {0x4e, 0x54, 0xf7, 0x0e,
                          0x5f, 0x5f, 0xc9, 0xf3,
                          0x84, 0xa6, 0x4f, 0xb2,
                          0x4e, 0xa6, 0xdc, 0x4f};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(7), key7, 16));

      // 8th round key
      uint8_t key8[16] = {0xea, 0xd2, 0x73, 0x21,
                          0xb5, 0x8d, 0xba, 0xd2,
                          0x31, 0x2b, 0xf5, 0x60,
                          0x7f, 0x8d, 0x29, 0x2f};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(8), key8, 16));

      // 9th round key
      uint8_t key9[16] = {0xac, 0x77, 0x66, 0xf3,
                          0x19, 0xfa, 0xdc, 0x21,
                          0x28, 0xd1, 0x29, 0x41,
                          0x57, 0x5c, 0x00, 0x6e};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(9), key9, 16));

      // 10th round key
      uint8_t key10[16] = {0xd0, 0x14, 0xf9, 0xa8,
                           0xc9, 0xee, 0x25, 0x89,
                           0xe1, 0x3f, 0x0c, 0xc8,
                           0xb6, 0x63, 0x0c, 0xa6};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(10), key10, 16));
    }

    TEST(AESKeyScheduleTest, test192KeySchedule)
    {
      char origKey[24];
      origKey[0] = 0x8e;
      origKey[1] = 0x73;
      origKey[2] = 0xb0;
      origKey[3] = 0xf7;
      origKey[4] = 0xda;
      origKey[5] = 0x0e; 
      origKey[6] = 0x64; 
      origKey[7] = 0x52;
      origKey[8] = 0xc8;
      origKey[9] = 0x10;
      origKey[10] = 0xf3;
      origKey[11] = 0x2b;
      origKey[12] = 0x80; 
      origKey[13] = 0x90; 
      origKey[14] = 0x79; 
      origKey[15] = 0xe5;
      origKey[16] = 0x62; 
      origKey[17] = 0xf8; 
      origKey[18] = 0xea; 
      origKey[19] = 0xd2;
      origKey[20] = 0x52; 
      origKey[21] = 0x2c; 
      origKey[22] = 0x6b;
      origKey[23] = 0x7b;

      AESKeySchedule keySched(AES::KeyLen::LEN_192, origKey);

      // 0th round key
      uint8_t key0[16] = {0x8e, 0x73, 0xb0, 0xf7,
                          0xda, 0x0e, 0x64, 0x52,
                          0xc8, 0x10, 0xf3, 0x2b,
                          0x80, 0x90, 0x79, 0xe5};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(0), key0, 16));

      // 1st round key
      uint8_t key1[16] = {0x62, 0xf8, 0xea, 0xd2,
                          0x52, 0x2c, 0x6b, 0x7b,
                          0xfe, 0x0c, 0x91, 0xf7,
                          0x24, 0x02, 0xf5, 0xa5};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(1), key1, 16));

      // 2nd round key
      uint8_t key2[16] = {0xec, 0x12, 0x06, 0x8e,
                          0x6c, 0x82, 0x7f, 0x6b,
                          0x0e, 0x7a, 0x95, 0xb9,
                          0x5c, 0x56, 0xfe, 0xc2};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(2), key2, 16));

      // 3rd round key
      uint8_t key3[16] = {0x4d, 0xb7, 0xb4, 0xbd,
                          0x69, 0xb5, 0x41, 0x18,
                          0x85, 0xa7, 0x47, 0x96,
                          0xe9, 0x25, 0x38, 0xfd};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(3), key3, 16));

      // 4th round key
      uint8_t key4[16] = {0xe7, 0x5f, 0xad, 0x44,
                          0xbb, 0x09, 0x53, 0x86,
                          0x48, 0x5a, 0xf0, 0x57,
                          0x21, 0xef, 0xb1, 0x4f};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(4), key4, 16));

      // 5th round key
      uint8_t key5[16] = {0xa4, 0x48, 0xf6, 0xd9,
                          0x4d, 0x6d, 0xce, 0x24,
                          0xaa, 0x32, 0x63, 0x60,
                          0x11, 0x3b, 0x30, 0xe6};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(5), key5, 16));

      // 6th round key
      uint8_t key6[16] = {0xa2, 0x5e, 0x7e, 0xd5,
                          0x83, 0xb1, 0xcf, 0x9a,
                          0x27, 0xf9, 0x39, 0x43,
                          0x6a, 0x94, 0xf7, 0x67};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(6), key6, 16));

      // 7th round key
      uint8_t key7[16] = {0xc0, 0xa6, 0x94, 0x07,
                          0xd1, 0x9d, 0xa4, 0xe1,
                          0xec, 0x17, 0x86, 0xeb,
                          0x6f, 0xa6, 0x49, 0x71};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(7), key7, 16));

      // 8th round key
      uint8_t key8[16] = {0x48, 0x5f, 0x70, 0x32,
                          0x22, 0xcb, 0x87, 0x55,
                          0xe2, 0x6d, 0x13, 0x52,
                          0x33, 0xf0, 0xb7, 0xb3};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(8), key8, 16));

      // 9th round key
      uint8_t key9[16] = {0x40, 0xbe, 0xeb, 0x28,
                          0x2f, 0x18, 0xa2, 0x59,
                          0x67, 0x47, 0xd2, 0x6b,
                          0x45, 0x8c, 0x55, 0x3e};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(9), key9, 16));

      // 10th round key
      uint8_t key10[16] = {0xa7, 0xe1, 0x46, 0x6c,
                           0x94, 0x11, 0xf1, 0xdf,
                           0x82, 0x1f, 0x75, 0x0a,
                           0xad, 0x07, 0xd7, 0x53};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(10), key10, 16));

      // 11th round key
      uint8_t key11[16] = {0xca, 0x40, 0x05, 0x38,
                           0x8f, 0xcc, 0x50, 0x06,
                           0x28, 0x2d, 0x16, 0x6a,
                           0xbc, 0x3c, 0xe7, 0xb5};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(11), key11, 16));

      // 12th round key
      uint8_t key12[16] = {0xe9, 0x8b, 0xa0, 0x6f,
                           0x44, 0x8c, 0x77, 0x3c,
                           0x8e, 0xcc, 0x72, 0x04,
                           0x01, 0x00, 0x22, 0x02};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(12), key12, 16));
    }

    TEST(AESKeyScheduleTest, test256KeySchedule)
    {
      char origKey[32];
      origKey[0] = 0x60;
      origKey[1] = 0x3d;
      origKey[2] = 0xeb;
      origKey[3] = 0x10;
      origKey[4] = 0x15;
      origKey[5] = 0xca;
      origKey[6] = 0x71;
      origKey[7] = 0xbe;
      origKey[8] = 0x2b; 
      origKey[9] = 0x73; 
      origKey[10] = 0xae;
      origKey[11] = 0xf0;
      origKey[12] = 0x85;
      origKey[13] = 0x7d;
      origKey[14] = 0x77;
      origKey[15] = 0x81;
      origKey[16] = 0x1f;
      origKey[17] = 0x35;
      origKey[18] = 0x2c;
      origKey[19] = 0x07;
      origKey[20] = 0x3b;
      origKey[21] = 0x61;
      origKey[22] = 0x08;
      origKey[23] = 0xd7;
      origKey[24] = 0x2d; 
      origKey[25] = 0x98; 
      origKey[26] = 0x10;
      origKey[27] = 0xa3;
      origKey[28] = 0x09;
      origKey[29] = 0x14;
      origKey[30] = 0xdf;
      origKey[31] = 0xf4;

      AESKeySchedule keySched(AES::KeyLen::LEN_256, origKey);

      // 0th round key
      uint8_t key0[16] = {0x60, 0x3d, 0xeb, 0x10,
                          0x15, 0xca, 0x71, 0xbe,
                          0x2b, 0x73, 0xae, 0xf0,
                          0x85, 0x7d, 0x77, 0x81};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(0), key0, 16));

      // 1st round key
      uint8_t key1[16] = {0x1f, 0x35, 0x2c, 0x07,
                          0x3b, 0x61, 0x08, 0xd7,
                          0x2d, 0x98, 0x10, 0xa3,
                          0x09, 0x14, 0xdf, 0xf4};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(1), key1, 16));

      // 2nd round key
      uint8_t key2[16] = {0x9b, 0xa3, 0x54, 0x11,
                          0x8e, 0x69, 0x25, 0xaf,
                          0xa5, 0x1a, 0x8b, 0x5f,
                          0x20, 0x67, 0xfc, 0xde};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(2), key2, 16));

      // 3rd round key
      uint8_t key3[16] = {0xa8, 0xb0, 0x9c, 0x1a,
                          0x93, 0xd1, 0x94, 0xcd,
                          0xbe, 0x49, 0x84, 0x6e,
                          0xb7, 0x5d, 0x5b, 0x9a};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(3), key3, 16));

      // 4th round key
      uint8_t key4[16] = {0xd5, 0x9a, 0xec, 0xb8,
                          0x5b, 0xf3, 0xc9, 0x17,
                          0xfe, 0xe9, 0x42, 0x48,
                          0xde, 0x8e, 0xbe, 0x96};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(4), key4, 16));

      // 5th round key
      uint8_t key5[16] = {0xb5, 0xa9, 0x32, 0x8a,
                          0x26, 0x78, 0xa6, 0x47,
                          0x98, 0x31, 0x22, 0x29,
                          0x2f, 0x6c, 0x79, 0xb3};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(5), key5, 16));

      // 6th round key
      uint8_t key6[16] = {0x81, 0x2c, 0x81, 0xad,
                          0xda, 0xdf, 0x48, 0xba,
                          0x24, 0x36, 0x0a, 0xf2,
                          0xfa, 0xb8, 0xb4, 0x64};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(6), key6, 16));

      // 7th round key
      uint8_t key7[16] = {0x98, 0xc5, 0xbf, 0xc9,
                          0xbe, 0xbd, 0x19, 0x8e,
                          0x26, 0x8c, 0x3b, 0xa7,
                          0x09, 0xe0, 0x42, 0x14};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(7), key7, 16));

      // 8th round key
      uint8_t key8[16] = {0x68, 0x00, 0x7b, 0xac,
                          0xb2, 0xdf, 0x33, 0x16,
                          0x96, 0xe9, 0x39, 0xe4,
                          0x6c, 0x51, 0x8d, 0x80};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(8), key8, 16));

      // 9th round key
      uint8_t key9[16] = {0xc8, 0x14, 0xe2, 0x04,
                          0x76, 0xa9, 0xfb, 0x8a,
                          0x50, 0x25, 0xc0, 0x2d,
                          0x59, 0xc5, 0x82, 0x39};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(9), key9, 16));

      // 10th round key
      uint8_t key10[16] = {0xde, 0x13, 0x69, 0x67,
                           0x6c, 0xcc, 0x5a, 0x71,
                           0xfa, 0x25, 0x63, 0x95,
                           0x96, 0x74, 0xee, 0x15};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(10), key10, 16));

      // 11th round key
      uint8_t key11[16] = {0x58, 0x86, 0xca, 0x5d,
                           0x2e, 0x2f, 0x31, 0xd7,
                           0x7e, 0x0a, 0xf1, 0xfa,
                           0x27, 0xcf, 0x73, 0xc3};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(11), key11, 16));

      // 12th round key
      uint8_t key12[16] = {0x74, 0x9c, 0x47, 0xab,
                           0x18, 0x50, 0x1d, 0xda,
                           0xe2, 0x75, 0x7e, 0x4f,
                           0x74, 0x01, 0x90, 0x5a};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(12), key12, 16));

      // 13th round key
      uint8_t key13[16] = {0xca, 0xfa, 0xaa, 0xe3,
                           0xe4, 0xd5, 0x9b, 0x34,
                           0x9a, 0xdf, 0x6a, 0xce,
                           0xbd, 0x10, 0x19, 0x0d};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(13), key13, 16));

      // 14th round key
      uint8_t key14[16] = {0xfe, 0x48, 0x90, 0xd1,
                           0xe6, 0x18, 0x8d, 0x0b,
                           0x04, 0x6d, 0xf3, 0x44,
                           0x70, 0x6c, 0x63, 0x1e};
      EXPECT_EQ(0, std::memcmp(keySched.getRoundKey(14), key14, 16));
    }

  }
}
