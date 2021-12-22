#ifndef LSKUSE_AES_BLOCK_TEST_H
#define LSKUSE_AES_BLOCK_TEST_H

#include "aeskeysched.h"

#include <memory>

#include <gtest/gtest.h>

namespace lskuse
{
  class AESBlockTest : public testing::Test
  {
    protected:
      AESBlockTest();

      //void SetUp() final;
      //void TearDown() final;

      AESKeySchedule m_keySched128;
      AESKeySchedule m_keySched192;
      AESKeySchedule m_keySched256;
  };
}

#endif // LSKUSE_AES_BLOCK_TEST_H
