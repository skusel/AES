#include "skusel/aes.h"
#include "aesblock.h"
#include "aeskeysched.h"

#include <fstream>

using namespace skusel;

/*************************************************************************************************/
AES::AES(Mode mode, Padding padding) :
  m_mode(mode), 
  m_padding(padding)
{
}

/*************************************************************************************************/
AES::Status AES::encrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& plaintextFile, std::string_view key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& plaintextFile, 
                         const std::array<char, 16>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& plaintextFile, 
                         const std::array<char, 24>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& plaintextFile, 
                         const std::array<char, 32>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  AES aes(mode, padding);
  return aes.encrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& ciphertextFile, std::string_view key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& ciphertextFile,
                         const std::array<char, 16>& key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& ciphertextFile,
                         const std::array<char, 24>& key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(Mode mode, Padding padding, 
                         const std::filesystem::path& ciphertextFile,
                         const std::array<char, 32>& key, 
                         const std::filesystem::path& plaintextFile)
{
  AES aes(mode, padding);
  return aes.decrypt(ciphertextFile, key, plaintextFile);
}
      
/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, std::string_view key, 
                         const std::filesystem::path& ciphertextFile)
{
  auto status = checkKeyLength(key);
  if(!status.m_success)
    return status;
  return runEncrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, 
                         const std::array<char, 16>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  return runEncrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, 
                         const std::array<char, 24>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  return runEncrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::encrypt(const std::filesystem::path& plaintextFile, 
                         const std::array<char, 32>& key, 
                         const std::filesystem::path& ciphertextFile)
{
  return runEncrypt(plaintextFile, key, ciphertextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile, std::string_view key, 
                         const std::filesystem::path& plaintextFile)
{
  auto status = checkKeyLength(key);
  if(!status.m_success)
    return status;
  return runDecrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile,
                         const std::array<char, 16>& key, 
                         const std::filesystem::path& plaintextFile)
{
  return runDecrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile,
                         const std::array<char, 24>& key, 
                         const std::filesystem::path& plaintextFile)
{
  return runDecrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::decrypt(const std::filesystem::path& ciphertextFile,
                         const std::array<char, 32>& key, 
                         const std::filesystem::path& plaintextFile)
{
  return runDecrypt(ciphertextFile, key, plaintextFile);
}

/*************************************************************************************************/
AES::Status AES::checkKeyLength(std::string_view key)
{
  AES::Status status;
  if(key.length() != 16 && key.length() != 24 && key.length() != 32)
  {
    status.m_success = false;
    status.m_message = "Key length must be 16, 24, or 32 characters.";
  }
  return status;
}

/*************************************************************************************************/
template<typename KeyType>
AES::Status AES::runEncrypt(const std::filesystem::path& plaintextFile, KeyType genericKey, 
                            const std::filesystem::path& ciphertextFile)
{
  /****************************************************************************
   * If we are in this function we have already verified the key length. Copy 
   * it over to a common representation (i.e., char[]).
   ***************************************************************************/
  char key[genericKey.size()];
  unsigned i = 0;
  for(char c : genericKey)
    key[i++] = c;

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

  AESKeySchedule keySchedule(genericKey.size(), key);

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
template<typename KeyType>
AES::Status AES::runDecrypt(const std::filesystem::path& ciphertextFile, KeyType genericKey, 
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

  /****************************************************************************
   * Key lengths should already be verified as 16, 24, or 32 bytes when
   * AESKeySchedule is constructed.
   ***************************************************************************/
  AESKeySchedule keySchedule(genericKey.size(), genericKey.data());
  
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

