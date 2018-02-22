#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_pre1.h"

#define BENCHMARKING

#ifdef BENCHMARKING
  #include "proxylib_benchmark.h"
#endif


#include <iostream>
#include <chrono>
#include <string>
#include <cstring>
#include <sys/time.h>

#ifdef BENCHMARKING
static struct timeval gTstart, gTend;
static struct timezone gTz;
extern Benchmark gBenchmark;
#endif

#ifdef BENCHMARKING
Benchmark gBenchmark(NUMBENCHMARKS);
// gBenchmark.InitOP(SCHEME_PRE1, 1000, )
#endif

Miracl precison(400, 0);
static CurveParams gParams;
using namespace std;

int main()
{

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
  std::chrono::high_resolution_clock::rep sum = 0;
  for (int i = 0; i < iterations; ++i)
  {
    auto t1 = std::chrono::high_resolution_clock::now();
    PRE1_level2_encrypt(gParams, plaintext1, pk1, ciphertext);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    sum += dur;
  }
  cout << "Average lvl2-encryption time: " << (double)sum / iterations << " ms" << endl;

  sum = 0;
  for (int i = 0; i < iterations; ++i)
  {
    auto t1 = std::chrono::high_resolution_clock::now();
    PRE1_reencrypt(gParams, ciphertext, delKey, newCiphertext);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    sum += dur;
    // std::cout << dur << " milliseconds" << endl;
  }
  cout << "Average re-encryption time: " << (double)sum / iterations << " ms" << endl;

  sum = 0;
  bool correct = true;
  for (int i = 0; i < iterations; ++i)
  {
    auto t1 = std::chrono::high_resolution_clock::now();
    PRE1_decrypt(gParams, newCiphertext, sk2, plaintext2);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    sum += dur;
    correct = correct && (plaintext1 == plaintext2);
  }
  cout << "Average decryption time: " << (double)sum / iterations << " ms. "
       << "All decryptions correct?: " << correct
       << endl;

  cout << gBenchmark << endl;

  return 0;
}