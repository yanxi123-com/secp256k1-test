#define HAVE_CONFIG_H 1
#define USE_NUM_GMP 1
#define USE_FIELD_10X26 1
#define USE_SCALAR_4X64 1

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/secp256k1.c"
#include "sha256/picosha2.h"

using namespace std;

const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

secp256k1_gej multi(const secp256k1_gej *p, const secp256k1_scalar *r) {
  secp256k1_gej point_result; // 点
  secp256k1_ecmult(NULL, &point_result, p, r, NULL);
  return point_result;
}

secp256k1_gej multi(const secp256k1_ge *p, const secp256k1_scalar *r) {
  secp256k1_gej p_gej;
  secp256k1_gej_set_ge(&p_gej, p);

  return multi(&p_gej, r);
}

secp256k1_gej get_r_point(const secp256k1_scalar *r) {
  secp256k1_gej point_g;
  secp256k1_gej_set_ge(&point_g, &secp256k1_ge_const_g);

  secp256k1_gej point_result; // 点
  secp256k1_ecmult(NULL, &point_result, &point_g, r, NULL);

  return point_result;
}

unsigned char char2int(char input) {
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  else return 0;
}

void hex2bin(const char* src, unsigned char* target) {
  while(*src && src[1]) {
    *(target++) = char2int(*src) * 16 + char2int(src[1]);
    src += 2;
  }
}

void hex_to_ge(std::string hex_str, secp256k1_ge *elem) {
  // std::string hex_str = "02cf9578f2c6386a5fdeddb8a9f3f57c3c5431dc88076cbe6ad574f04b29103044";
  unsigned char pub[33];
  hex2bin(hex_str.c_str(), pub);
  secp256k1_eckey_pubkey_parse(elem, pub, 33);
}

void hex_to_scalar(std::string hex_str, secp256k1_scalar &scalar) {
  unsigned char sc[32];
  hex2bin(hex_str.c_str(), sc);
  secp256k1_scalar_set_b32(&scalar, sc, NULL);
}

// string ge_to_hex(secp256k1_ge *elem) {
//   unsigned char pub[33];
//   size_t size;
//   secp256k1_eckey_pubkey_serialize(elem, pub, &size, true);

//   std::vector<unsigned char> char_vector;
//   for (unsigned char c : pub) {
//     char_vector.emplace_back(c);
//   }

//   std::ostringstream oss;
//   picosha2::output_hex(char_vector.begin(), char_vector.end(), oss);
//   std::string hex_str;
//   hex_str.assign(oss.str());

//   return hex_str;
// }

string ge_to_hex(secp256k1_ge *elem) {
  unsigned char pub[33];
  size_t size;
  secp256k1_eckey_pubkey_serialize(elem, pub, &size, true);

  std::string s(66, ' ');
  for (int i = 0; i < 33; ++i) {
    s[2 * i]     = hexmap[(pub[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[pub[i] & 0x0F];
  }
  return s;
}

string gej_to_hex(secp256k1_gej *gej) {
  secp256k1_ge ge;
  secp256k1_ge_set_gej(&ge, gej);
  return ge_to_hex(&ge);
}

secp256k1_gej pri_to_pub_gej(string private_hex) {
  secp256k1_scalar key_private;  // 随机数
  hex_to_scalar(private_hex, key_private);

  return get_r_point(&key_private);
}

string pri_to_pub(string private_hex) {
  secp256k1_gej p_gej = pri_to_pub_gej(private_hex);
  secp256k1_ge p_ge;
  secp256k1_ge_set_gej(&p_ge, &p_gej);
  return ge_to_hex(&p_ge);
}

static void secp256k1_bulletproof_update_commit(unsigned char *commit, const secp256k1_ge *lpt, const secp256k1_ge *rpt) {
  secp256k1_fe pointx;
  secp256k1_sha256 sha256;
  unsigned char lrparity;
  lrparity = (!secp256k1_fe_is_quad_var(&lpt->y) << 1) + !secp256k1_fe_is_quad_var(&rpt->y);
  secp256k1_sha256_initialize(&sha256);
  secp256k1_sha256_write(&sha256, commit, 32);
  secp256k1_sha256_write(&sha256, &lrparity, 1);

  pointx = lpt->x;
  secp256k1_fe_normalize(&pointx);
  secp256k1_fe_get_b32(commit, &pointx);
  secp256k1_sha256_write(&sha256, commit, 32);
  
  pointx = rpt->x;
  secp256k1_fe_normalize(&pointx);
  secp256k1_fe_get_b32(commit, &pointx);
  secp256k1_sha256_write(&sha256, commit, 32);
  
  secp256k1_sha256_finalize(&sha256, commit);
}

