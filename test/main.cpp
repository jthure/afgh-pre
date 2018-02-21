#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_pre1.h"

#include <iostream>
#include <chrono>

Miracl precison(50, 0);
static CurveParams gParams;
using namespace std;

int main() {

    initLibrary();
    PRE1_generate_params(gParams);

    ProxyPK_PRE1 pk1;
    ProxySK_PRE1 sk1;
    PRE1_keygen(gParams, pk1, sk1);
    char b[600];
    int len = pk1.serialize(SERIALIZE_HEXASCII, b, 600);
    cout << b << endl;
    ProxyPK_PRE1 pk2;
    ProxySK_PRE1 sk2;
    PRE1_keygen(gParams, pk2, sk2);
    ECn delKey;
    PRE1_delegate(gParams, pk2, sk1, delKey);

    Big plaintext1 = 100;
    cout << plaintext1.bits() << endl;
    Big plaintext2 = 0;
    ProxyCiphertext_PRE1 ciphertext;
    ProxyCiphertext_PRE1 newCiphertext;
    PRE1_level2_encrypt(gParams, plaintext1, pk1, ciphertext);
    

    for(int i = 0; i< 1000; ++i){
        auto t1 = std::chrono::high_resolution_clock::now();
        PRE1_reencrypt(gParams, ciphertext, delKey, newCiphertext);
        auto t2 = std::chrono::high_resolution_clock::now();
        std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()
                  << " milliseconds\n";


    }
    
    PRE1_decrypt(gParams, newCiphertext, sk2, plaintext2);

    if(plaintext1 == plaintext2){
        cout << "Success" << endl;
    } else {
        cout << "Fail" << endl;
        }
    return 0;
}