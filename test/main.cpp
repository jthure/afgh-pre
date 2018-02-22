#define BENCHMARKING

#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_pre1.h"

#ifdef BENCHMARKING
  #include "proxylib_benchmark.h"
#endif


#include <iostream>
#include <chrono>
#include <string>
#include <cstring>
#include <sys/time.h>
#include <functional>

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif

#ifdef BENCHMARKING
Benchmark gBenchmark(NUMBENCHMARKS);
#endif

Miracl precision(400, 0);
static CurveParams gParams;
using namespace std;

int call_n_times(function<void()> func, size_t n){
  for(size_t i = 0; i < n; ++i){
    func();
  }
}

int main()
{

  InitBenchmarks(gBenchmark, 100);

  initLibrary();
  PRE1_generate_params(gParams);

  ProxyPK_PRE1 pk1;
  ProxySK_PRE1 sk1;
  PRE1_keygen(gParams, pk1, sk1);
  char b[600];
  int len = pk1.serialize(SERIALIZE_HEXASCII, b, 600);
  // cout << b << endl;
  ProxyPK_PRE1 pk2;
  ProxySK_PRE1 sk2;
  PRE1_keygen(gParams, pk2, sk2);
  ECn delKey;
  PRE1_delegate(gParams, pk2, sk1, delKey);

  string plaintext_string = string(32, 'F');
  char *c_plaintext_string = new char[plaintext_string.length() + 1];
  std::strcpy(c_plaintext_string, plaintext_string.c_str());
  Big plaintext1(c_plaintext_string);
  cout << "Length of plaintext in bits: " << plaintext1.bits() << endl;
  Big plaintext2 = 0;
  ProxyCiphertext_PRE1 ciphertext;
  ProxyCiphertext_PRE1 newCiphertext;

  int iterations = 100;
  call_n_times([&plaintext1, &pk1, &ciphertext] {
    PRE1_level2_encrypt(gParams, plaintext1, pk1, ciphertext);
  }, iterations);
  call_n_times([&ciphertext, &delKey, &newCiphertext] {
    PRE1_reencrypt(gParams, ciphertext, delKey, newCiphertext);
  }, iterations);
  call_n_times([&newCiphertext, &sk2, &plaintext2] {
    PRE1_decrypt(gParams, newCiphertext, sk2, plaintext2);
  }, iterations);
  cout << gBenchmark << endl;

  return 0;
}