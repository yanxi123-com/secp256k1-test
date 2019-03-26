#include <string>
#include <iostream>
#include "crypto.cpp"

static secp256k1_rfc6979_hmac_sha256 secp256k1_test_rng;

static void secp256k1_rand256(unsigned char *b32) {
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, b32, 32);
}

void test_pri_to_pub() {
  secp256k1_scalar key_private;  // 随机数
  string private_hex = "298c037a59679f33d2597bc10f15cd042f71a60f3d219ec88fde42f3e55b1e4f";
  string hex_str = pri_to_pub(private_hex);
  cout << "private: " << private_hex << endl;
  cout << "public : " << hex_str << endl;
}

void test_multi() {
  string private_hex1 = "73414346fa4736fe688686ed598c698687446b094bd83735dba1439095228094";
  string private_hex2 = "06a76a4e75e4e9f022d17fa1476e415af7ec096c00b90766c9b2b88c5f8d14d4";

  secp256k1_scalar scalar1, scalar2;
  hex_to_scalar(private_hex1, scalar1);
  hex_to_scalar(private_hex2, scalar2);

  secp256k1_gej public_gej1 = pri_to_pub_gej(private_hex1);
  secp256k1_gej public_gej2 = pri_to_pub_gej(private_hex2);

  secp256k1_gej gej1 = multi(&public_gej1, &scalar2);
  secp256k1_gej gej2 = multi(&public_gej2, &scalar1);
  
  cout << "private_hex1: " << private_hex1 << endl;
  cout << "private_hex2: " << private_hex2 << endl;

  cout << "public_hex1: " << gej_to_hex(&public_gej1) << endl;
  cout << "public_hex2: " << gej_to_hex(&public_gej2) << endl;
  
  cout << "public_1 * private_2: " << gej_to_hex(&gej1) << endl;
  cout << "public_2 * private_1: " << gej_to_hex(&gej2) << endl;
}

int main(int argc, char **argv) {
  test_multi();
}
