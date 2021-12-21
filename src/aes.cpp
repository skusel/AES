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
  
  unsigned fileSize = std::filesystem::file_size(plaintextFile, ec);
  if(ec)
  {
    status.m_success = false;
    status.m_message = "Could not obtain the size of the plaintext file";
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
      unsigned numBytesRead = 0;
      unsigned plaintextLen = 0;
      while(plainFile)
      {
        char plaintext[AESBlock::sizeInBytes()];
        plainFile.read(plaintext, AESBlock::sizeInBytes());
        plaintextLen = plainFile.gcount();
        numBytesRead += plaintextLen;
        bool lastBlock = (numBytesRead >= fileSize && numBytesRead != AESBlock::sizeInBytes());
        AESBlock block(m_padding, keySchedule, reinterpret_cast<uint8_t*>(plaintext), plaintextLen, lastBlock);
        const uint8_t* ciphertext = block.encrypt();
        cipherFile.write(reinterpret_cast<const char*>(ciphertext), AESBlock::sizeInBytes());
      }
      if(m_padding == Padding::PKCS7 && plaintextLen == AESBlock::sizeInBytes())
      {
        // last block was fully filled, add a block of just padding
        uint8_t plaintext[AESBlock::sizeInBytes()];
        AESBlock block(m_padding, keySchedule, plaintext, 0, true);
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

  unsigned fileSize = std::filesystem::file_size(ciphertextFile, ec);
  if(ec)
  {
    status.m_success = false;
    status.m_message = "Could not obtain the size of the ciphertext file";
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
      unsigned numBytesRead = 0;
      while(cipherFile)
      {
        char ciphertext[AESBlock::sizeInBytes()];
        cipherFile.read(ciphertext, AESBlock::sizeInBytes());
        unsigned ciphertextLen = cipherFile.gcount();
        if(ciphertextLen != AESBlock::sizeInBytes())
        {
          status.m_success = false;
          status.m_message = "Invalid ciphertext block found";
          return status;
        }
        numBytesRead += ciphertextLen;
        bool lastBlock = (numBytesRead >= fileSize);
        AESBlock block(m_padding, keySchedule, reinterpret_cast<uint8_t*>(ciphertext), ciphertextLen, lastBlock);
        auto [plaintext, plaintextLen] = block.decrypt();
        if(plaintextLen != 0)
          plainFile.write(reinterpret_cast<const char*>(plaintext), plaintextLen);
      }
      break;
    }
  }

  return status;
}

