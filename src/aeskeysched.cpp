#include "aeskeysched.h"
#include "sboxes.h"

using namespace lskuse;

/*************************************************************************************************/
AESKeySchedule::AESKeySchedule(AES::KeyLen keyLen, const std::string& key, bool isEncrypt) :
  m_keyLen(keyLen),
  m_key(key),
  m_isEncrypt(isEncrypt)
{
  computeKeySchedule()
}

/*************************************************************************************************/
char* AESKeySchedule::getRoundKey(unsigned round)
{
  // TODO: access round key from m_keySchedule vector
  return nullptr;
}

/*************************************************************************************************/
void AESKeySchedule::computeKeySchedule()
{
  // TODO: compute the key schedule using AES KeySchedule algorithm and the original key
}

/*************************************************************************************************/
void AESKeySchedule::rotWord()
{
  // TODO: implement 32-bit work rotation
}

/*************************************************************************************************/
void AESKeySchedule::subWord()
{
  // TODO: implement byte-substition using AESBlock s-boxes
}

/*************************************************************************************************/
void AESKeySchedule::rcon()
{
  // TODO: implement round constant
}

