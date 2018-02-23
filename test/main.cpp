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
#include <cstdlib>

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif

#ifdef BENCHMARKING
Benchmark gBenchmark(NUMBENCHMARKS);
#endif

Miracl precision(32, 0);
static CurveParams gParams;
using namespace std;

int call_n_times(function<void()> func, size_t n){
  for(size_t i = 0; i < n; ++i){
    func();
  }
}

int main() {
  InitBenchmarks(gBenchmark, 1000);
  initLibrary();
  PRE1_generate_params(gParams);
  
  ProxyPK_PRE1 pk1, pk2;
  ProxySK_PRE1 sk1, sk2;
  ProxyCiphertext_PRE1 lvl1Ciphertext, lvl2Ciphertext, reencryptedCiphertext;
  ECn reencKey;
  Big plaintext1;
  Big plaintext2;

  miracl *mip = &precision;
  mip->IOBASE = 16;
  std::srand(std::time(nullptr));
  const int STR_LEN = 32;
  const size_t ITERATIONS = 10;
  char plaintext_str[STR_LEN + 1];
  size_t iter, str_iter;
  
  for ( iter = 0; iter < ITERATIONS; ++iter)
  {
    for (str_iter = 0; str_iter < STR_LEN; ++str_iter)
    {
      sprintf(plaintext_str + str_iter, "%X", std::rand() % 16);
    }
    // cout << plaintext_str << endl;
    plaintext1 = plaintext_str;
    plaintext2 = 0;
    PRE1_keygen(gParams, pk1, sk1);
    PRE1_keygen(gParams, pk2, sk2);
    PRE1_delegate(gParams, pk2, sk1, reencKey);
    PRE1_level2_encrypt(gParams, plaintext1, pk1, lvl2Ciphertext);
    PRE1_level1_encrypt(gParams, plaintext1, pk1, lvl1Ciphertext);
    PRE1_reencrypt(gParams, lvl2Ciphertext, reencKey, reencryptedCiphertext);
    PRE1_decrypt(gParams, reencryptedCiphertext, sk2, plaintext2);
    PRE1_decrypt(gParams, lvl2Ciphertext, sk1, plaintext2);
    PRE1_decrypt(gParams, lvl1Ciphertext, sk1, plaintext2);
  }
  cout << gBenchmark << endl;
  return 0;
}