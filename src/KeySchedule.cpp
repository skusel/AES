#include "KeySchedule.h"
#include "sboxes.h"

using namespace lskuse;

/*************************************************************************************************/
KeySchedule::KeySchedule(AES::KeyLen keyLen, const std::string& key) :
  m_keyLen(keyLen),
  m_key(key)
{
  computeKeySchedule()
}

/*************************************************************************************************/
char* KeySchedule::getRoundKey(unsigned round)
{
  // TODO: access round key from m_keySchedule vector
  return nullptr;
}

/*************************************************************************************************/
void KeySchedule::computeKeySchedule()
{
  // TODO: compute the key schedule using AES KeySchedule algorithm and the original key
}

/*************************************************************************************************/
void KeySchedule::rotWord()
{
  // TODO: implement 32-bit work rotation
}

/*************************************************************************************************/
void KeySchedule::subWord()
{
  // TODO: implement byte-substition using AESBlock s-boxes
}

/*************************************************************************************************/
void KeySchedule::rcon()
{
  // TODO: implement round constant
}

