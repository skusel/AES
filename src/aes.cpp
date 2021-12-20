#include "lskuse/aes.h"
#include "aesblock.h"
#include "aeskeysched.h"

#include <fstream>

using namespace lskuse;

/*************************************************************************************************/
AES::AES(Mode mode, KeyLen keyLen, Padding padding) :
  m_mode(mode), 
  m_keyLen(keyLen), 
  m_padding(padding)
{
}

/*************************************************************************************************/
bool AES::encrypt(Mode mode, KeyLen keyLen, Padding padding, 
                  const std::filesystem::path& plaintextFile, const std::string& key, 
                  const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
bool AES::decrypt(Mode mode, KeyLen keyLen, Padding padding, 
                  const std::filesystem::path& ciphertextFile, const std::string& key, 
                  const std::filesystem::path& plaintextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
bool AES::encrypt(const std::filesystem::path& plaintextFile, const std::string& key, 
                  const std::filesystem::path& ciphertextFile)
{
  if(!std::filesystem::exists(plaintextFile))
    return false;

  std::ifstream plainFile(plaintextFile, std::ios::binary);
  if(!plainFile.good())
    return false;

  std::ofstream cipherFile(ciphertextFile, std::ios::binary);
  if(!cipherFile.good())
    return false;

  AESKeySchedule keySchedule(m_keyLen, key);
  if(!keySchedule.isValid())
    return false;

  switch(m_mode)
  {
    case Mode::ECB:
    {
      while(plainFile)
      {
        char plaintext[AESBlock::sizeInBytes()];
        plainFile.read(plaintext, AESBlock::sizeInBytes());
        int plaintextLen = plainFile.gcount();
        AESBlock block(m_padding, keySchedule, reinterpret_cast<uint8_t*>(plaintext), plaintextLen);
        const uint8_t* ciphertext = block.encrypt();
        cipherFile.write(reinterpret_cast<const char*>(ciphertext), AESBlock::sizeInBytes());
      }
      break;
    }
  }

  return true;
}

/*************************************************************************************************/
bool AES::decrypt(const std::filesystem::path& ciphertextFile, const std::string& key, 
                  const std::filesystem::path& plaintextFile)
{
  if(!std::filesystem::exists(ciphertextFile))
    return false;
  
  std::ifstream cipherFile(ciphertextFile, std::ios::binary);
  if(!cipherFile.good())
    return false;

  std::ofstream plainFile(plaintextFile, std::ios::binary);
  if(!plainFile.good())
    return false;

  AESKeySchedule keySchedule(m_keyLen, key);
  if(!keySchedule.isValid())
    return false;
  
  switch(m_mode)
  {
    case Mode::ECB:
    {
      while(cipherFile)
      {
        char ciphertext[AESBlock::sizeInBytes()];
        cipherFile.read(ciphertext, AESBlock::sizeInBytes());
        AESBlock block(m_padding, keySchedule, reinterpret_cast<uint8_t*>(ciphertext));
        auto [plaintext, plaintextLen] = block.decrypt();
        plainFile.write(reinterpret_cast<const char*>(plaintext), plaintextLen);
      }
      break;
    }
  }

  return true;
}

