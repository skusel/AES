#include "aesblock.h"
#include "aessboxes.h"

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

  addRoundKey(0);
  
  for(unsigned round = 1; round < m_keySchedule.getNumRounds(); round++)
  {
    byteSub();
    shiftRow();
    mixCol();
    addRoundKey(round);
  }
  
  // last round does not perform mixCol
  byteSub();
  shiftRow();
  addRoundKey(m_keySchedule.getNumRounds());

  return m_state;
}

/*************************************************************************************************/
std::pair<const uint8_t*, int> AESBlock::decrypt()
{
  std::memcpy(m_state, m_data, BLOCK_SIZE_BYTES);

  // first round does not perform mixCol
  addRoundKey(m_keySchedule.getNumRounds());
  invShiftRow();
  invByteSub();

  for(unsigned round = m_keySchedule.getNumRounds() - 1; round > 0; round--)
  {
    addRoundKey(round);
    invMixCol();
    invShiftRow();
    invByteSub();
  }

  addRoundKey(0);

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
unsigned AESBlock::removePadding()
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
uint8_t AESBlock::gfmult(uint8_t a, uint8_t b)
{
  /****************************************************************************
   * This function implements GF(2^8) mulitplication using a variation of 
   * peasent multiplication. This algo takes advantage of multiplication's 
   * distributive property.
   * 
   * e.g. 4 * 9 = 4 * (1* 2^0 + 0 * 2^1 + 0 * 2^2 + 1 * 2^3)
   *
   * Algorithm described in...
   * https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
   ***************************************************************************/
  uint8_t p = 0;
  while(a != 0 && b != 0)
  {
    if(b & 1)
      p ^= a;              // finite field addition
    b >>= 1;
    if(a & 0x80)
      a = (a << 1) ^ 0x1b; // multiply a by 2 then xor with irreducible polynomial
    else
      a <<= 1;
  }
  return p;
}

/*************************************************************************************************/
void AESBlock::byteSub()
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i++)
    m_state[i] = AES_SBOX[m_state[i]];
}

/*************************************************************************************************/
void AESBlock::shiftRow()
{
  uint8_t m_tmpState[BLOCK_SIZE_BYTES];
  std::memcpy(m_tmpState, m_state, BLOCK_SIZE_BYTES);
  m_state[0] = m_tmpState[0];
  m_state[1] = m_tmpState[5];
  m_state[2] = m_tmpState[10];
  m_state[3] = m_tmpState[15];
  m_state[4] = m_tmpState[4];
  m_state[5] = m_tmpState[9];
  m_state[6] = m_tmpState[14];
  m_state[7] = m_tmpState[3];
  m_state[8] = m_tmpState[8];
  m_state[9] = m_tmpState[13];
  m_state[10] = m_tmpState[2];
  m_state[11] = m_tmpState[7];
  m_state[12] = m_tmpState[12];
  m_state[13] = m_tmpState[1];
  m_state[14] = m_tmpState[6];
  m_state[15] = m_tmpState[11];
}

/*************************************************************************************************/
void AESBlock::mixCol()
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i += WORD_SIZE_BYTES)
  {
    uint8_t s[WORD_SIZE_BYTES];
    s[0] = gfmult(2, m_state[i]) ^ gfmult(3, m_state[i + 1]) ^ m_state[i + 2] ^ m_state[i + 3];
    s[1] = m_state[i] ^ gfmult(2, m_state[i + 1]) ^ gfmult(3, m_state[i + 2]) ^ m_state[i + 3];
    s[2] = m_state[i] ^ m_state[i + 1] ^ gfmult(2, m_state[i + 2]) ^ gfmult(3, m_state[i + 3]);
    s[3] = gfmult(3, m_state[i]) ^ m_state[i + 1] ^ m_state[i + 2] ^ gfmult(2, m_state[i + 3]);
    std::memcpy(m_state + i, s, WORD_SIZE_BYTES);
  }
}

/*************************************************************************************************/
void AESBlock::invByteSub()
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i++)
    m_state[i] = AES_INVERSE_SBOX[m_state[i]];
}

/*************************************************************************************************/
void AESBlock::invShiftRow()
{
  uint8_t m_tmpState[BLOCK_SIZE_BYTES];
  std::memcpy(m_tmpState, m_state, BLOCK_SIZE_BYTES);
  m_state[0] = m_tmpState[0];
  m_state[1] = m_tmpState[13];
  m_state[2] = m_tmpState[10];
  m_state[3] = m_tmpState[7];
  m_state[4] = m_tmpState[4];
  m_state[5] = m_tmpState[1];
  m_state[6] = m_tmpState[14];
  m_state[7] = m_tmpState[11];
  m_state[8] = m_tmpState[8];
  m_state[9] = m_tmpState[5];
  m_state[10] = m_tmpState[2];
  m_state[11] = m_tmpState[15];
  m_state[12] = m_tmpState[12];
  m_state[13] = m_tmpState[9];
  m_state[14] = m_tmpState[6];
  m_state[15] = m_tmpState[3];
}

/*************************************************************************************************/
void AESBlock::invMixCol()
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i += WORD_SIZE_BYTES)
  {
    uint8_t s[WORD_SIZE_BYTES];
    s[0] = gfmult(14, m_state[i]) ^ gfmult(11, m_state[i + 1]) ^ gfmult(13, m_state[i + 2]) ^ gfmult(9, m_state[i + 3]);
    s[1] = gfmult(9, m_state[i]) ^ gfmult(14, m_state[i + 1]) ^ gfmult(11, m_state[i + 2]) ^ gfmult(13, m_state[i + 3]);
    s[2] = gfmult(13, m_state[i]) ^ gfmult(9, m_state[i + 1]) ^ gfmult(14, m_state[i + 2]) ^ gfmult(11, m_state[i + 3]);
    s[3] = gfmult(11, m_state[i]) ^ gfmult(13, m_state[i + 1]) ^ gfmult(9, m_state[i + 2]) ^ gfmult(14, m_state[i + 3]);
    std::memcpy(m_state + i, s, WORD_SIZE_BYTES);
  }
}

/*************************************************************************************************/
void AESBlock::addRoundKey(unsigned round)
{
  for(unsigned i = 0; i < BLOCK_SIZE_BYTES; i++)
    m_state[i] ^= m_keySchedule.getRoundKey(round)[i];
}

