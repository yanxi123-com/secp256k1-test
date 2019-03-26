cd tests

g++ -std=c++17 \
  -I ../src \
  -I ./secp256k1 \
  -I ./secp256k1/src \
  -I ./secp256k1/src/modules/ecdh \
  -o test test.cpp  \
  -lgmp -lgmpxx

# g++ -std=c++17 \
#   -I ./secp256k1 \
#   -I ./secp256k1/src \
#   -I ./secp256k1/src/modules/ecdh \
#   -o test secp256k1/src/tests.c \
#   -lgmp -lgmpxx

