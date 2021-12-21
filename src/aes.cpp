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
AES::Status AES::encrypt(Mode mode, KeyLen keyLen, Padding padding, 
                         const std::filesystem::path& plaintextFile, const std::string& key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, KeyLen keyLen, Padding padding, 
                         const std::filesystem::path& ciphertextFile, const std::string& key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, const std::string& key, 
                         const std::filesystem::path& ciphertextFile)
{
  Status status;

  std::error_code ec;
  if(!std::filesystem::exists(plaintextFile, ec) || ec)
  {
    status.m_success = false;
    status.m_message = "The plaintext file does not exist";
    return status;
  }

  std::ifstream plainFile(plaintextFile, std::ios::binary);
  if(!plainFile.good())
  {
    status.m_success = false;
    status.m_message = "The plaintext file could not be read";
    return status;
  }

  std::ofstream cipherFile(ciphertextFile, std::ios::binary);
  if(!cipherFile.good())
  {
    status.m_success = false;
    status.m_message = "The ciphertext file could not be written to";
    return status;
  }

  AESKeySchedule keySchedule(m_keyLen, key);
  if(!keySchedule.isValid())
  {
    status.m_success = false;
    status.m_message = "An invalid key was provided";
    return status;
  }

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

  return status;
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile, const std::string& key, 
                         const std::filesystem::path& plaintextFile)
{
  Status status;

  std::error_code ec;
  if(!std::filesystem::exists(ciphertextFile) || ec)
  {
    status.m_success = false;
    status.m_message = "The ciphertext file does not exist";
    return status;
  }
  
  std::ifstream cipherFile(ciphertextFile, std::ios::binary);
  if(!cipherFile.good())
  {
    status.m_success = false;
    status.m_message = "The ciphertext file could not be read";
    return status;
  }

  std::ofstream plainFile(plaintextFile, std::ios::binary);
  if(!plainFile.good())
  {
    status.m_success = false;
    status.m_message = "The plaintext file could not be written to";
    return status;
  }

  AESKeySchedule keySchedule(m_keyLen, key);
  if(!keySchedule.isValid())
  {
    status.m_success = false;
    status.m_message = "An invalid key was provided";
    return status;
  }
  
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

  return status;
}

