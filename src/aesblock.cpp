#include "aesblock.h"
#include "sboxes.h"

#include <cstring>
#include <iostream>

using namespace lskuse;

/*************************************************************************************************/
AESBlock::AESBlock(AES::Padding padding, const AESKeySchedule& keySchedule, const uint8_t* data, 
                   unsigned dataLen, bool lastBlock) :
  m_padding(padding),
  m_keySchedule(keySchedule),
  m_data(data), 
  m_dataLen(dataLen),
  m_lastBlock(lastBlock)
{
}

/*************************************************************************************************/
const uint8_t* AESBlock::encrypt()
{
  std::memcpy(m_state, m_data, m_dataLen);
  if(m_lastBlock)
    pad();

  return m_state;
}

/*************************************************************************************************/
std::pair<const uint8_t*, int> AESBlock::decrypt()
{
  std::memcpy(m_state, m_data, BLOCK_SIZE_BYTES);
  int plaintextLen = BLOCK_SIZE_BYTES;
  if(m_lastBlock)
    plaintextLen = removePadding();

  return std::make_pair(m_state, plaintextLen);
}

/*************************************************************************************************/
void AESBlock::pad()
{
  if(m_dataLen < BLOCK_SIZE_BYTES)
  {
    switch(m_padding)
    {
      case AES::Padding::PKCS7:
      {
        uint8_t numMissingBytes = BLOCK_SIZE_BYTES - m_dataLen;
        for(unsigned i = m_dataLen; i < BLOCK_SIZE_BYTES; i++)
          m_state[i] = numMissingBytes;
        break;
      }
    }
  }
}

/*************************************************************************************************/
int AESBlock::removePadding()
{
  switch(m_padding)
  {
    case AES::Padding::PKCS7:
    {
      uint8_t padVal = m_state[BLOCK_SIZE_BYTES - 1];
      bool validPad = true;
      for(unsigned i = BLOCK_SIZE_BYTES - 2; i >= BLOCK_SIZE_BYTES - padVal; i--)
      {
        if(m_state[i] != padVal)
          validPad = false;
        
        if(i == 0)
          break; // prevent neg value from creating segfault since using unsigned
      }
      return validPad ? BLOCK_SIZE_BYTES - padVal : BLOCK_SIZE_BYTES;
    }
  }
  return BLOCK_SIZE_BYTES;
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
void AESBlock::addRoundKey(unsigned round)
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i++)
    m_state[i] ^= m_keySchedule.getRoundKey(round)[i];
}

