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
                         const std::filesystem::path& plaintextFile, const char* key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, KeyLen keyLen, Padding padding, 
                         const std::filesystem::path& ciphertextFile, const char* key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, keyLen, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, const char* key, 
                         const std::filesystem::path& ciphertextFile)
{
  Status status;
  
  if(ciphertextFile == plaintextFile)
  {
    status.m_success = false;
    status.m_message = "The plaintext file and ciphertext file cannot be the same";
    return status;
  }

  std::error_code ec;
  if(!std::filesystem::exists(plaintextFile, ec) || ec)
  {
    status.m_success = false;
    status.m_message = "Cannot encrypt a plaintext file that does not exist";
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

  switch(m_mode)
  {
    case Mode::ECB:
    {
      unsigned numBytesRead = 0;
      while(plainFile)
      {
        char plaintext[AESBlock::sizeInBytes()];
        plainFile.read(plaintext, AESBlock::sizeInBytes());
        // plaintextLen will be set to 0 if reached end and entire last block was filled
        unsigned plaintextLen = plainFile.gcount();
        numBytesRead += plaintextLen;
        bool lastBlock = (numBytesRead >= fileSize && plaintextLen != AESBlock::sizeInBytes());
        AESBlock block(m_padding, keySchedule, reinterpret_cast<uint8_t*>(plaintext), plaintextLen, lastBlock);
        const uint8_t* ciphertext = block.encrypt();
        cipherFile.write(reinterpret_cast<const char*>(ciphertext), AESBlock::sizeInBytes());
      }
      break;
    }
  }

  return status;
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile, const char* key, 
                         const std::filesystem::path& plaintextFile)
{
  Status status;

  if(ciphertextFile == plaintextFile)
  {
    status.m_success = false;
    status.m_message = "The ciphertext file and plaintext file cannot be the same";
    return status;
  }

  std::error_code ec;
  if(!std::filesystem::exists(ciphertextFile) || ec)
  {
    status.m_success = false;
    status.m_message = "Cannot decrypt a ciphertext file that does not exist";
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
        if(ciphertextLen == 0)
          break;
        else if(ciphertextLen != AESBlock::sizeInBytes())
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

