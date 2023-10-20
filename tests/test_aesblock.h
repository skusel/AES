#ifndef SKUSEL_AES_BLOCK_TEST_H
#define SKUSEL_AES_BLOCK_TEST_H

#include "aeskeysched.h"

#include <gtest/gtest.h>

namespace skusel
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

#endif // SKUSEL_AES_BLOCK_TEST_H
