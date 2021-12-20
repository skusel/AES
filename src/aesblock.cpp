#include "aesblock.h"
#include "sboxes.h"

#include <cstring>

using namespace lskuse;

/*************************************************************************************************/
AESBlock::AESBlock(AES::Padding padding, const AESKeySchedule& keySchedule, const uint8_t* data, 
                   int dataLen) :
  m_padding(padding),
  m_keySchedule(keySchedule),
  m_data(data), 
  m_dataLen(dataLen)
{
}

/*************************************************************************************************/
const uint8_t* AESBlock::encrypt()
{
  std::memcpy(m_state, m_data, m_dataLen);
  pad();

  return m_state;
}

/*************************************************************************************************/
std::pair<const uint8_t*, int> AESBlock::decrypt()
{
  std::memcpy(m_state, m_data, BLOCK_SIZE_BYTES);
  int plaintextLen = removePadding();

  return std::make_pair(m_state, plaintextLen);
}

/*************************************************************************************************/
void AESBlock::pad()
{
  // TODO: implement padding logic if plaintext is not 16 bytes
  if(m_dataLen != BLOCK_SIZE_BYTES)
  {
    if(m_padding == AES::Padding::ISO)
      m_state[15] = 0; // this needs to be replaced with actual logic
  }
}

/*************************************************************************************************/
int AESBlock::removePadding()
{
  // TODO: implement remove padding logic if ciphertext was padded
  return 12; // this needs to be replaced with the actual plaintext length
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

