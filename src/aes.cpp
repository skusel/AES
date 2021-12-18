#include "lskuse/aes.h"
#include "aesblock.h"
#include "aeskeysched.h"

using namespace lskuse;

/*************************************************************************************************/
AES::AES(Mode mode, KeyLen keyLen, Padding padding) :
  m_mode(mode), 
  m_keyLen(keyLen), 
  m_padding(padding)
{
}

/*************************************************************************************************/
std::string AES::encrypt(const std::string& plaintext, const std::string& key, 
                         Mode mode, KeyLen keyLen, Padding padding)
{
  AES aes(mode, keyLen, padding);
  return aes.encrypt(plaintext, key);
}

/*************************************************************************************************/
std::string AES::decrypt(const std::string& ciphertext, const std::string& key, 
                         Mode mode, KeyLen keyLen, Padding padding)
{
  AES aes(mode, keyLen, padding);
  return aes.decrypt(ciphertext, key);
}

/*************************************************************************************************/
std::string AES::encrypt(const std::string& plaintext, const std::string& key)
{
  std::string ciphertext;

  AESKeySchedule keySchedule(m_keyLen, key);
  switch(m_mode)
  {
    case Mode::ECB:
    {
      // ECB encrypts blocks separately
      for(unsigned i = 0; i < plaintext.size(); i += AESBlock::sizeInBytes())
      {
        AESBlock block(m_padding, plaintext.substr(i, AESBlock::sizeInBytes()), keySchedule);
        ciphertext += block.encrypt();
      }
      break;
    }
    case Mode::CBC:
    {
      // TODO: implement CBC encryption
      break;
    }
  }

  return ciphertext;
}

/*************************************************************************************************/
std::string AES::decrypt(const std::string& ciphertext, const std::string& key)
{
  std::string plaintext;

  AESKeySchedule keySchedule(m_keyLen, key);
  switch(m_mode)
  {
    case Mode::ECB:
    {
      // ECB decrypts blocks separately
      for(unsigned i = 0; i < ciphertext.size(); i += AESBlock::sizeInBytes())
      {
        AESBlock block(m_padding, ciphertext.substr(i, AESBlock::sizeInBytes()), keySchedule);
        plaintext += block.decrypt();
      }
      break;
    }
    case Mode::CBC:
    {
      // TODO: implement CBC decryption
      break;
    }
  }

  return plaintext;
}

