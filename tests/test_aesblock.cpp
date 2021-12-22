#include "test_aesblock.h"

#include "aesblock.h"

namespace lskuse
{
  /*********************************************************************************************/
  AESBlockTest::AESBlockTest() :
    m_keySched128(AES::KeyLen::LEN_128, "DFhUR7md38I&54fz"),
    m_keySched192(AES::KeyLen::LEN_192, "jf83*fhn#nfuDrR*JF3FeEr3"),
    m_keySched256(AES::KeyLen::LEN_256, "H+1XrImy0acc&S|E=yHF5%MUm3-hP*MG")
  {
  }

  /*********************************************************************************************/
  TEST_F(AESBlockTest, testBlockEncryption)
  {
    /**************************************************************************
     * Known values obtained from...
     * https://www.codeusingjava.com/tools/aes
     *************************************************************************/

    const char* plaintext0 = "One whole block!";
    AESBlock block0(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext0), 
                    AESBlock::sizeInBytes(), false);
    const uint8_t* ciphertext0 = block0.encrypt();
    EXPECT_EQ(ciphertext0[0], 0x1e);
    EXPECT_EQ(ciphertext0[1], 0x93);
    EXPECT_EQ(ciphertext0[2], 0x2e);
    EXPECT_EQ(ciphertext0[3], 0x67);
    EXPECT_EQ(ciphertext0[4], 0xb9);
    EXPECT_EQ(ciphertext0[5], 0x12);
    EXPECT_EQ(ciphertext0[6], 0xef);
    EXPECT_EQ(ciphertext0[7], 0xaf);
    EXPECT_EQ(ciphertext0[8], 0xb7);
    EXPECT_EQ(ciphertext0[9], 0x75);
    EXPECT_EQ(ciphertext0[10], 0x3c);
    EXPECT_EQ(ciphertext0[11], 0x42);
    EXPECT_EQ(ciphertext0[12], 0xa9);
    EXPECT_EQ(ciphertext0[13], 0xa4);
    EXPECT_EQ(ciphertext0[14], 0x61);
    EXPECT_EQ(ciphertext0[15], 0xe2);

    const char* plaintext1 = "Hello test";
    AESBlock block1(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext1), 10, true);
    const uint8_t* ciphertext1 = block1.encrypt();
    EXPECT_EQ(ciphertext1[0], 0x28);
    EXPECT_EQ(ciphertext1[1], 0x52);
    EXPECT_EQ(ciphertext1[2], 0xac);
    EXPECT_EQ(ciphertext1[3], 0xb6);
    EXPECT_EQ(ciphertext1[4], 0x20);
    EXPECT_EQ(ciphertext1[5], 0x71);
    EXPECT_EQ(ciphertext1[6], 0x00);
    EXPECT_EQ(ciphertext1[7], 0x15);
    EXPECT_EQ(ciphertext1[8], 0x88);
    EXPECT_EQ(ciphertext1[9], 0x48);
    EXPECT_EQ(ciphertext1[10], 0x34);
    EXPECT_EQ(ciphertext1[11], 0xb1);
    EXPECT_EQ(ciphertext1[12], 0x39);
    EXPECT_EQ(ciphertext1[13], 0x54);
    EXPECT_EQ(ciphertext1[14], 0xd0);
    EXPECT_EQ(ciphertext1[15], 0x48);

    const char* plaintext2 = "";
    AESBlock block2(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(plaintext2), 0, true);
    const uint8_t* ciphertext2 = block2.encrypt();
    EXPECT_EQ(ciphertext2[0], 0x37);
    EXPECT_EQ(ciphertext2[1], 0x51);
    EXPECT_EQ(ciphertext2[2], 0xbb);
    EXPECT_EQ(ciphertext2[3], 0x31);
    EXPECT_EQ(ciphertext2[4], 0xb1);
    EXPECT_EQ(ciphertext2[5], 0x75);
    EXPECT_EQ(ciphertext2[6], 0xa0);
    EXPECT_EQ(ciphertext2[7], 0xa7);
    EXPECT_EQ(ciphertext2[8], 0xb9);
    EXPECT_EQ(ciphertext2[9], 0xcd);
    EXPECT_EQ(ciphertext2[10], 0xa7);
    EXPECT_EQ(ciphertext2[11], 0xf9);
    EXPECT_EQ(ciphertext2[12], 0xb1);
    EXPECT_EQ(ciphertext2[13], 0xc6);
    EXPECT_EQ(ciphertext2[14], 0x6d);
    EXPECT_EQ(ciphertext2[15], 0x8b);

    const char* plaintext3 = "One whole block!";
    AESBlock block3(AES::Padding::PKCS7, m_keySched192, reinterpret_cast<const uint8_t*>(plaintext3), 
                    AESBlock::sizeInBytes(), false);
    const uint8_t* ciphertext3 = block3.encrypt();
    EXPECT_EQ(ciphertext3[0], 0x64);
    EXPECT_EQ(ciphertext3[1], 0x52);
    EXPECT_EQ(ciphertext3[2], 0xa1);
    EXPECT_EQ(ciphertext3[3], 0xe5);
    EXPECT_EQ(ciphertext3[4], 0xc7);
    EXPECT_EQ(ciphertext3[5], 0x0d);
    EXPECT_EQ(ciphertext3[6], 0xc4);
    EXPECT_EQ(ciphertext3[7], 0x32);
    EXPECT_EQ(ciphertext3[8], 0x91);
    EXPECT_EQ(ciphertext3[9], 0x39);
    EXPECT_EQ(ciphertext3[10], 0xe6);
    EXPECT_EQ(ciphertext3[11], 0xf6);
    EXPECT_EQ(ciphertext3[12], 0xe7);
    EXPECT_EQ(ciphertext3[13], 0x30);
    EXPECT_EQ(ciphertext3[14], 0x07);
    EXPECT_EQ(ciphertext3[15], 0xf2);

    const char* plaintext4 = "One whole block!";
    AESBlock block4(AES::Padding::PKCS7, m_keySched256, reinterpret_cast<const uint8_t*>(plaintext4), 
                    AESBlock::sizeInBytes(), false);
    const uint8_t* ciphertext4 = block4.encrypt();
    EXPECT_EQ(ciphertext4[0], 0x39);
    EXPECT_EQ(ciphertext4[1], 0xa7);
    EXPECT_EQ(ciphertext4[2], 0x84);
    EXPECT_EQ(ciphertext4[3], 0x99);
    EXPECT_EQ(ciphertext4[4], 0x5b);
    EXPECT_EQ(ciphertext4[5], 0xae);
    EXPECT_EQ(ciphertext4[6], 0xef);
    EXPECT_EQ(ciphertext4[7], 0xf2);
    EXPECT_EQ(ciphertext4[8], 0x78);
    EXPECT_EQ(ciphertext4[9], 0x61);
    EXPECT_EQ(ciphertext4[10], 0x00);
    EXPECT_EQ(ciphertext4[11], 0x27);
    EXPECT_EQ(ciphertext4[12], 0xe9);
    EXPECT_EQ(ciphertext4[13], 0x4b);
    EXPECT_EQ(ciphertext4[14], 0xdd);
    EXPECT_EQ(ciphertext4[15], 0x67);
  }

  /*********************************************************************************************/
  TEST_F(AESBlockTest, testBlockDecryption)
  {
    const char* initText0 = "One whole block!";
    AESBlock eblock0(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(initText0), 16, false);
    const uint8_t* ciphertext0 = eblock0.encrypt();
    AESBlock dblock0(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext0), 
                     AESBlock::sizeInBytes(), false);
    auto [plaintext0, plaintext0Len] = dblock0.decrypt();
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

    const char* initText1 = "Hello test";
    AESBlock eblock1(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(initText1), 10, true);
    const uint8_t* ciphertext1 = eblock1.encrypt();
    AESBlock dblock1(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext1), 
                     AESBlock::sizeInBytes(), true);
    auto [plaintext1, plaintext1Len] = dblock1.decrypt();
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

    const char* initText2 = "";
    AESBlock eblock2(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(initText2), 0, true);
    const uint8_t* ciphertext2 = eblock2.encrypt();
    AESBlock dblock2(AES::Padding::PKCS7, m_keySched128, reinterpret_cast<const uint8_t*>(ciphertext2), 
                     AESBlock::sizeInBytes(), true);
    auto [plaintext2, plaintext2Len] = dblock2.decrypt();
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

    const char* initText3 = "One whole block!";
    AESBlock eblock3(AES::Padding::PKCS7, m_keySched192, reinterpret_cast<const uint8_t*>(initText3), 16, false);
    const uint8_t* ciphertext3 = eblock3.encrypt();
    AESBlock dblock3(AES::Padding::PKCS7, m_keySched192, reinterpret_cast<const uint8_t*>(ciphertext3), 
                     AESBlock::sizeInBytes(), false);
    auto [plaintext3, plaintext3Len] = dblock3.decrypt();
    EXPECT_EQ(plaintext3Len, 16);
    EXPECT_EQ(plaintext3[0], 0x4f);
    EXPECT_EQ(plaintext3[1], 0x6e);
    EXPECT_EQ(plaintext3[2], 0x65);
    EXPECT_EQ(plaintext3[3], 0x20);
    EXPECT_EQ(plaintext3[4], 0x77);
    EXPECT_EQ(plaintext3[5], 0x68);
    EXPECT_EQ(plaintext3[6], 0x6f);
    EXPECT_EQ(plaintext3[7], 0x6c);
    EXPECT_EQ(plaintext3[8], 0x65);
    EXPECT_EQ(plaintext3[9], 0x20);
    EXPECT_EQ(plaintext3[10], 0x62);
    EXPECT_EQ(plaintext3[11], 0x6c);
    EXPECT_EQ(plaintext3[12], 0x6f);
    EXPECT_EQ(plaintext3[13], 0x63);
    EXPECT_EQ(plaintext3[14], 0x6b);
    EXPECT_EQ(plaintext3[15], 0x21);

    const char* initText4 = "One whole block!";
    AESBlock eblock4(AES::Padding::PKCS7, m_keySched256, reinterpret_cast<const uint8_t*>(initText4), 16, false);
    const uint8_t* ciphertext4 = eblock4.encrypt();
    AESBlock dblock4(AES::Padding::PKCS7, m_keySched256, reinterpret_cast<const uint8_t*>(ciphertext4), 
                     AESBlock::sizeInBytes(), false);
    auto [plaintext4, plaintext4Len] = dblock4.decrypt();
    EXPECT_EQ(plaintext4Len, 16);
    EXPECT_EQ(plaintext4[0], 0x4f);
    EXPECT_EQ(plaintext4[1], 0x6e);
    EXPECT_EQ(plaintext4[2], 0x65);
    EXPECT_EQ(plaintext4[3], 0x20);
    EXPECT_EQ(plaintext4[4], 0x77);
    EXPECT_EQ(plaintext4[5], 0x68);
    EXPECT_EQ(plaintext4[6], 0x6f);
    EXPECT_EQ(plaintext4[7], 0x6c);
    EXPECT_EQ(plaintext4[8], 0x65);
    EXPECT_EQ(plaintext4[9], 0x20);
    EXPECT_EQ(plaintext4[10], 0x62);
    EXPECT_EQ(plaintext4[11], 0x6c);
    EXPECT_EQ(plaintext4[12], 0x6f);
    EXPECT_EQ(plaintext4[13], 0x63);
    EXPECT_EQ(plaintext4[14], 0x6b);
    EXPECT_EQ(plaintext4[15], 0x21);
  }
}
