#include "test_aesblock.h"

#include "aesblock.h"

namespace lskuse
{
  /*********************************************************************************************/
  AESBlockTest::AESBlockTest() :
    m_keySched128(AES::KeyLen::LEN_128, "DFhUR7md38I&54fzP")
  {
  }

  /*********************************************************************************************/
  TEST_F(AESBlockTest, testBlockEncryption)
  {
    const char* plaintext0 = "One whole block!";
    AESBlock block0(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext0), 
                    AESBlock::sizeInBytes(), false);
    const uint8_t* ciphertext0 = block0.encrypt();
    EXPECT_EQ(ciphertext0[0], 0x4f);
    EXPECT_EQ(ciphertext0[1], 0x6e);
    EXPECT_EQ(ciphertext0[2], 0x65);
    EXPECT_EQ(ciphertext0[3], 0x20);
    EXPECT_EQ(ciphertext0[4], 0x77);
    EXPECT_EQ(ciphertext0[5], 0x68);
    EXPECT_EQ(ciphertext0[6], 0x6f);
    EXPECT_EQ(ciphertext0[7], 0x6c);
    EXPECT_EQ(ciphertext0[8], 0x65);
    EXPECT_EQ(ciphertext0[9], 0x20);
    EXPECT_EQ(ciphertext0[10], 0x62);
    EXPECT_EQ(ciphertext0[11], 0x6c);
    EXPECT_EQ(ciphertext0[12], 0x6f);
    EXPECT_EQ(ciphertext0[13], 0x63);
    EXPECT_EQ(ciphertext0[14], 0x6b);
    EXPECT_EQ(ciphertext0[15], 0x21);

    const char* plaintext1 = "Hello test";
    AESBlock block1(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext1), 10, true);
    const uint8_t* ciphertext1 = block1.encrypt();
    EXPECT_EQ(ciphertext1[0], 0x48);
    EXPECT_EQ(ciphertext1[1], 0x65);
    EXPECT_EQ(ciphertext1[2], 0x6c);
    EXPECT_EQ(ciphertext1[3], 0x6c);
    EXPECT_EQ(ciphertext1[4], 0x6f);
    EXPECT_EQ(ciphertext1[5], 0x20);
    EXPECT_EQ(ciphertext1[6], 0x74);
    EXPECT_EQ(ciphertext1[7], 0x65);
    EXPECT_EQ(ciphertext1[8], 0x73);
    EXPECT_EQ(ciphertext1[9], 0x74);
    EXPECT_EQ(ciphertext1[10], 0x06);
    EXPECT_EQ(ciphertext1[11], 0x06);
    EXPECT_EQ(ciphertext1[12], 0x06);
    EXPECT_EQ(ciphertext1[13], 0x06);
    EXPECT_EQ(ciphertext1[14], 0x06);
    EXPECT_EQ(ciphertext1[15], 0x06);

    const char* plaintext2 = "";
    AESBlock block2(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext2), 0, true);
    const uint8_t* ciphertext2 = block2.encrypt();
    EXPECT_EQ(ciphertext2[0], 0x10);
    EXPECT_EQ(ciphertext2[1], 0x10);
    EXPECT_EQ(ciphertext2[2], 0x10);
    EXPECT_EQ(ciphertext2[3], 0x10);
    EXPECT_EQ(ciphertext2[4], 0x10);
    EXPECT_EQ(ciphertext2[5], 0x10);
    EXPECT_EQ(ciphertext2[6], 0x10);
    EXPECT_EQ(ciphertext2[7], 0x10);
    EXPECT_EQ(ciphertext2[8], 0x10);
    EXPECT_EQ(ciphertext2[9], 0x10);
    EXPECT_EQ(ciphertext2[10], 0x10);
    EXPECT_EQ(ciphertext2[11], 0x10);
    EXPECT_EQ(ciphertext2[12], 0x10);
    EXPECT_EQ(ciphertext2[13], 0x10);
    EXPECT_EQ(ciphertext2[14], 0x10);
    EXPECT_EQ(ciphertext2[15], 0x10);
  }

  /*********************************************************************************************/
  TEST_F(AESBlockTest, testBlockDecryption)
  {
    const char* ciphertext0 = "One whole block!";
    AESBlock block0(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext0), 
                    AESBlock::sizeInBytes(), false);
    auto [plaintext0, plaintext0Len] = block0.decrypt();
    EXPECT_EQ(plaintext0Len, 16);
    EXPECT_EQ(plaintext0[0], 0x4f);
    EXPECT_EQ(plaintext0[1], 0x6e);
    EXPECT_EQ(plaintext0[2], 0x65);
    EXPECT_EQ(plaintext0[3], 0x20);
    EXPECT_EQ(plaintext0[4], 0x77);
    EXPECT_EQ(plaintext0[5], 0x68);
    EXPECT_EQ(plaintext0[6], 0x6f);
    EXPECT_EQ(plaintext0[7], 0x6c);
    EXPECT_EQ(plaintext0[8], 0x65);
    EXPECT_EQ(plaintext0[9], 0x20);
    EXPECT_EQ(plaintext0[10], 0x62);
    EXPECT_EQ(plaintext0[11], 0x6c);
    EXPECT_EQ(plaintext0[12], 0x6f);
    EXPECT_EQ(plaintext0[13], 0x63);
    EXPECT_EQ(plaintext0[14], 0x6b);
    EXPECT_EQ(plaintext0[15], 0x21);

    char ciphertext1[AESBlock::sizeInBytes()];
    ciphertext1[0] = 'H';
    ciphertext1[1] = 'e';
    ciphertext1[2] = 'l';
    ciphertext1[3] = 'l';
    ciphertext1[4] = 'o';
    ciphertext1[5] = ' ';
    ciphertext1[6] = 't';
    ciphertext1[7] = 'e'; 
    ciphertext1[8] = 's';
    ciphertext1[9] = 't';
    ciphertext1[10] = 0x06;
    ciphertext1[11] = 0x06;
    ciphertext1[12] = 0x06;
    ciphertext1[13] = 0x06;
    ciphertext1[14] = 0x06;
    ciphertext1[15] = 0x06;
    AESBlock block1(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext1), 
                    AESBlock::sizeInBytes(), true);
    auto [plaintext1, plaintext1Len] = block1.decrypt();
    EXPECT_EQ(plaintext1Len, 10);
    EXPECT_EQ(plaintext1[0], 0x48);
    EXPECT_EQ(plaintext1[1], 0x65);
    EXPECT_EQ(plaintext1[2], 0x6c);
    EXPECT_EQ(plaintext1[3], 0x6c);
    EXPECT_EQ(plaintext1[4], 0x6f);
    EXPECT_EQ(plaintext1[5], 0x20);
    EXPECT_EQ(plaintext1[6], 0x74);
    EXPECT_EQ(plaintext1[7], 0x65);
    EXPECT_EQ(plaintext1[8], 0x73);
    EXPECT_EQ(plaintext1[9], 0x74);
    EXPECT_EQ(plaintext1[10], 0x06);
    EXPECT_EQ(plaintext1[11], 0x06);
    EXPECT_EQ(plaintext1[12], 0x06);
    EXPECT_EQ(plaintext1[13], 0x06);
    EXPECT_EQ(plaintext1[14], 0x06);
    EXPECT_EQ(plaintext1[15], 0x06);

    const char ciphertext2[AESBlock::sizeInBytes()] = {0x10, 0x10, 0x10, 0x10,
                                                       0x10, 0x10, 0x10, 0x10, 
                                                       0x10, 0x10, 0x10, 0x10, 
                                                       0x10, 0x10, 0x10, 0x10};
    AESBlock block2(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext2), 
                    AESBlock::sizeInBytes(), true);
    auto [plaintext2, plaintext2Len] = block2.decrypt();
    EXPECT_EQ(plaintext2Len, 0);
    EXPECT_EQ(plaintext2[0], 0x10);
    EXPECT_EQ(plaintext2[1], 0x10);
    EXPECT_EQ(plaintext2[2], 0x10);
    EXPECT_EQ(plaintext2[3], 0x10);
    EXPECT_EQ(plaintext2[4], 0x10);
    EXPECT_EQ(plaintext2[5], 0x10);
    EXPECT_EQ(plaintext2[6], 0x10);
    EXPECT_EQ(plaintext2[7], 0x10);
    EXPECT_EQ(plaintext2[8], 0x10);
    EXPECT_EQ(plaintext2[9], 0x10);
    EXPECT_EQ(plaintext2[10], 0x10);
    EXPECT_EQ(plaintext2[11], 0x10);
    EXPECT_EQ(plaintext2[12], 0x10);
    EXPECT_EQ(plaintext2[13], 0x10);
    EXPECT_EQ(plaintext2[14], 0x10);
    EXPECT_EQ(plaintext2[15], 0x10);
  }
}
