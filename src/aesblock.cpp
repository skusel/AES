#include "aesblock.h"
#include "sboxes.h"

#include <cstring>

using namespace lskuse;

/*************************************************************************************************/
AESBlock::AESBlock(AES::Padding padding, const std::string& data, const KeySchedule& keySchedule) :
  m_padding(padding),
  m_data(data), 
  m_keySchedule(keySchedule)
{
}

/*************************************************************************************************/
std::string AESBlock::encrypt()
{
  std::string paddedPlaintext = pad(m_data);

  std::memcpy(m_state, paddedPlaintext.c_str(), BLOCK_SIZE_BYTES);

  return m_state;
}

/*************************************************************************************************/
std::string AESBlock::decrypt()
{
  std::memcpy(m_state, m_data.c_str(), BLOCK_SIZE_BYTES);

  return unpad(m_state);
}

/*************************************************************************************************/
std::string AESBlock::pad(const std::string& plaintext)
{
  // TODO: implement padding logic if plaintext is not 16 bytes
  return plaintext;
}

/*************************************************************************************************/
std::string AESBlock::unpad(const std::string& paddedPlaintext)
{
  // TODO: implement remove padding logic if ciphertext was padded
  return paddedPlaintext;
}

/*************************************************************************************************/
void AESBlock::byteSub()
{
  // TODO: implement byteSub
}

/*************************************************************************************************/
void AESBlock::shiftRow()
{
  // TODO: implement shiftRow
}

/*************************************************************************************************/
void AESBlock::mixCol()
{
  // TODO: implement mixCol
}

/*************************************************************************************************/
void AESBlock::invByteSub()
{
  // TODO: implement invByteSub
}

/*************************************************************************************************/
void AESBlock::invShiftRow()
{
  // TODO: implement invShiftRow
}

/*************************************************************************************************/
void AESBlock::invMixCol()
{
  // TODO: implement invMixCol
}

/*************************************************************************************************/
void AESBlock::addRoundKey()
{
  // TODO:: implement addRoundKey
}

