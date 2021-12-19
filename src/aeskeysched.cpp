#include "aeskeysched.h"
#include "sboxes.h"

#include <cassert>

using namespace lskuse;

/*************************************************************************************************/
AESKeySchedule::AESKeySchedule(AES::KeyLen keyLen, const std::string& key, bool isEncrypt) :
  m_keyLen(keyLen),
  m_key(key),
  m_isEncrypt(isEncrypt),
  m_valid(true)
{
  computeKeySchedule()
}

/*************************************************************************************************/
AESKeySchedule::~AESKeySchedule()
{
  for(const auto& roundKey : m_keySchedule)
    delete roundKey;
}

/*************************************************************************************************/
char* AESKeySchedule::getRoundKey(unsigned round) const
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
     (m_keyLen == AES::KeyLen::LNE_256 && m_key.size() != LEN_256_IN_BYTES))
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
  char W[LEN_128_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_128_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the transformation 10 times to get a total of 11 round keys
  for(unsigned wordRow = 0; wordRow < LEN_128_TRANSFORMATIONS; wordRow++)
  {
    char nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWork(nextW);
    rcon(nextW);
    for(unsigned word = 0; word < LEN_128_IN_BYTES / WORD_LEN; word++)
    {
      nextW ^= W[wIdx - LEN_128_IN_BYTES];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }

  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_128_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    char* roundKey = new char[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.insert(roundKey);
  }

  assert(m_keySchedule.size() == 11);
}

/*************************************************************************************************/
void AESKeySchedule::compute192KeySchedule()
{
  // grab the first 6 words
  unsigned wIdx = 0;
  char W[LEN_192_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_192_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the tranformation 9 times to get a total of 13 round keys
  for(unsigned wordRow = 0; wordRow < LEN_192_TRANSFORMATIONS; wordRow++)
  {
    char nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWork(nextW);
    rcon(nextW);
    for(unsigned word = 0; word < LEN_192_IN_BYTES / WORD_LEN; word++)
    {
      nextW ^= W[wIdx - LEN_192_IN_BYTES];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }

  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_192_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    char* roundKey = new char[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.insert(roundKey);
  }

  assert(m_keySchedule.size() == 13);
}

/*************************************************************************************************/
void AESKeySchedule::compute256KeySchedule()
{
  // grab the first 8 words
  unsigned wIdx = 0;
  char W[LEN_256_WORD_ARRAY_SIZE];
  for(unsigned byteIdx = 0; byteIdx < LEN_256_IN_BYTES; byteIdx++)
    W[wIdx++] = m_key.data()[byteIdx];

  // apply the transformation 8 times to get a total of 15 round keys
  for(unsigned round = 0; round < LEN_256_TRANSFORMATIONS; round++)
  {
    char nextW[WORD_LEN];
    std::memcpy(nextW, W + wIdx - WORD_LEN, WORD_LEN);
    rotWord(nextW);
    subWord(nextW);
    rcon(nextW);
    for(unsigned word = 0; word < LEN_256_IN_BYTES / WORD_LEN; word++)
    {
      if(word == LEN_256_IN_BYTES / WORD_LEN / 2 - 1)
        subWord(nextW); // extra step in 256 bit AES key schedule
      nextW ^= W[wIdx - LEN_256_IN_BYTES];
      std::memcpy(W + wIdx, nextW, WORD_LEN);
      wIdx += WORD_LEN;
    }
  }
  
  // populate our key schedule in ROUND_KEY_LEN strides
  for(unsigned round = 0; round < LEN_256_WORD_ARRAY_SIZE / ROUND_KEY_LEN; round++)
  {
    char* roundKey = new char[ROUND_KEY_LEN];
    std::memcpy(roundKey, W + (round * ROUND_KEY_LEN), ROUND_KEY_LEN);
    m_keySchedule.insert(roundKey);
  }

  assert(m_keySchedule.size() == 16); // added an extra key to simplify the algo
}

/*************************************************************************************************/
void AESKeySchedule::rotWord(char* word)
{
  char tmp = word[0];
  std::memmove(word, word + 1, WORD_LEN - 1);
  word[WORD_LEN - 1] = tmp;
}

/*************************************************************************************************/
void AESKeySchedule::subWord(char* word)
{
  for(unsigned i = 0; i < WORD_LEN; i++)
    word[i] = AES::SBOX[word[i]];
}

/*************************************************************************************************/
void AESKeySchedule::rcon(char* word, unsigned round)
{
  word[0] ^= RCON[round];
}

