#include "cryptlite/sha1.h"
#include "cryptlite/sha256.h"
#include "cryptlite/base64.h"
#include "cryptlite/hmac.h"
#include <gtest/gtest.h>

using namespace cryptlite;

TEST(hmacTest, testCalc)
{
  EXPECT_EQ("2dd4349aa2f20d7a1d6bafbc5807fcb5c82520c1", hmac<sha1>::calc_hex("base", "key"));
  EXPECT_EQ("023ce1cd22309757263392d7b68c82405bf45daf686e825260e1edd1adb83578", hmac<sha256>::calc_hex("base", "key"));

  /*const char* base = "base";
  const char* key  = "key";
  boost::uint8_t digest[32];*/

  const char* key = "ULSJwtSigningKeyHeiHei";
  const char* base  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsInZlcnNpb24iOiIxIn0.eyJ1c2VyX2lkIjo1LCJleHBpcmF0aW9uIjo4NjQwMDAwMCwiYXV0aF9ncm91cCI6ImZhY2VSZWNvZ25pdGlvbiIsInBsYXRmb3JtIjowLCJiaW5kX2NvbnRlbnQiOiIiLCJjb3VudCI6MH0";
  uint8_t digest[32];

  hmac<sha256>::calc(base, strlen(base), key, strlen(key), digest);
  //EXPECT_EQ("AjzhzSIwl1cmM5LXtoyCQFv0Xa9oboJSYOHt0a24NXg=", base64::encode_from_array(digest, 32));

  std::cout<<std::endl<<base64::encode_from_array(digest, 32)<<std::endl;
  std::string base2 = "base";
  std::string key2  = "key";
  uint8_t digest2[32];
  hmac<sha256>::calc(base2, key2, digest2);
  EXPECT_EQ("AjzhzSIwl1cmM5LXtoyCQFv0Xa9oboJSYOHt0a24NXg=", base64::encode_from_array(digest2, 32));
}

