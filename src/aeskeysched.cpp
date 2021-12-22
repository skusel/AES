#include "aeskeysched.h"
#include "aessboxes.h"

#include <cassert>
#include <cstring>

using namespace lskuse;

/*************************************************************************************************/
AESKeySchedule::AESKeySchedule(AES::KeyLen keyLen, const std::string& key) :
  m_keyLen(keyLen),
  m_key(key),
  m_valid(true)
{
  computeKeySchedule();
}

/*************************************************************************************************/
AESKeySchedule::~AESKeySchedule()
{
  for(auto& roundKey : m_keySchedule)
  {
    if(roundKey != nullptr)
      delete [] roundKey;
    roundKey = nullptr;
  }
}

/*************************************************************************************************/
unsigned AESKeySchedule::getNumRounds() const
{
  switch(m_keyLen)
  {
    case AES::KeyLen::LEN_128:
      return 10;
    case AES::KeyLen::LEN_192:
      return 12;
    case AES::KeyLen::LEN_256:
      return 14;
    default:
      return m_keySchedule.size() - 1;
  }
}

/*************************************************************************************************/
uint8_t* AESKeySchedule::getRoundKey(unsigned round) const
{
  if(!isValid() || round >= m_keySchedule.size())
    return nullptr;
  else
    return m_keySchedule[round];
}

/*************************************************************************************************/
void AESKeySchedule::computeKeySchedule()
{
  if((m_keyLen == AES::KeyLen::LEN_128 && m_key.size() != LEN_128_IN_BYTES) ||
     (m_keyLen == AES::KeyLen::LEN_192 && m_key.size() != LEN_192_IN_BYTES) ||
     (m_keyLen == AES::KeyLen::LEN_256 && m_key.size() != LEN_256_IN_BYTES))
  {
    m_valid = false;
  }

  if(m_keyLen == AES::KeyLen::LEN_128)
    compute128KeySchedule();
  else if(m_keyLen == AES::KeyLen::LEN_192)
    compute192KeySchedule();
  else
    compute256KeySchedule();
}

/*************************************************************************************************/
void AESKeySchedule::compute128KeySchedule()
{
  // grab the first 4 words
  unsigned wIdx = 0;
  uint8_t W[LEN_128_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_128_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the transformation 10 times to get a total of 11 round keys
  for(unsigned transformation = 0; transformation < LEN_128_TRANSFORMATIONS; transformation++)
  {
    uint8_t nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWord(nextW);
    rcon(nextW, transformation);
    for(unsigned word = 0; word < LEN_128_IN_BYTES / WORD_LEN; word++)
    {
      for(unsigned byte = 0; byte < WORD_LEN; byte++)
        nextW[byte] ^= W[wIdx - LEN_128_IN_BYTES + byte];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }

  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_128_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    uint8_t* roundKey = new uint8_t[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.push_back(roundKey);
  }

  assert(m_keySchedule.size() == 11);
}

/*************************************************************************************************/
void AESKeySchedule::compute192KeySchedule()
{
  // grab the first 6 words
  unsigned wIdx = 0;
  uint8_t W[LEN_192_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_192_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the tranformation 9 times to get a total of 13 round keys
  for(unsigned transformation = 0; transformation < LEN_192_TRANSFORMATIONS; transformation++)
  {
    uint8_t nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWord(nextW);
    rcon(nextW, transformation);
    for(unsigned word = 0; word < LEN_192_IN_BYTES / WORD_LEN; word++)
    {
      for(unsigned byte = 0; byte < WORD_LEN; byte++)
        nextW[byte] ^= W[wIdx - LEN_192_IN_BYTES + byte];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }

  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_192_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    uint8_t* roundKey = new uint8_t[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.push_back(roundKey);
  }

  assert(m_keySchedule.size() == 13);
}

/*************************************************************************************************/
void AESKeySchedule::compute256KeySchedule()
{
  // grab the first 8 words
  unsigned wIdx = 0;
  uint8_t W[LEN_256_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_256_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the transformation 8 times to get a total of 15 round keys
  for(unsigned transformation = 0; transformation < LEN_256_TRANSFORMATIONS; transformation++)
  {
    uint8_t nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWord(nextW);
    rcon(nextW, transformation);
    for(unsigned word = 0; word < LEN_256_IN_BYTES / WORD_LEN; word++)
    {
      if(word == LEN_256_IN_BYTES / WORD_LEN / 2)
        subWord(nextW); // extra step in 256 bit AES key schedule
      for(unsigned byte = 0; byte < WORD_LEN; byte++)
        nextW[byte] ^= W[wIdx - LEN_256_IN_BYTES + byte];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }
  
  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_256_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    uint8_t* roundKey = new uint8_t[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.push_back(roundKey);
  }

  assert(m_keySchedule.size() == 16); // added an extra key to simplify the algo
}

/*************************************************************************************************/
void AESKeySchedule::rotWord(uint8_t* word)
{
  uint8_t tmp = word[0];
  std::memmove(word, word + 1, WORD_LEN - 1);
  word[WORD_LEN - 1] = tmp;
}

/*************************************************************************************************/
void AESKeySchedule::subWord(uint8_t* word)
{
  for(unsigned i = 0; i < WORD_LEN; i++)
    word[i] = AES_SBOX[word[i]];
}

/*************************************************************************************************/
void AESKeySchedule::rcon(uint8_t* word, unsigned round)
{
  word[0] ^= RCON[round];
}

