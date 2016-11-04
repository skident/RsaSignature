#include <iostream>

#include <Poco/Crypto/RSAKey.h>
#include "RsaWorker.hpp"


using namespace std;
using namespace Poco::Crypto;

int main()
{
	RSAKey publicKey("RSA_keys\\public.key");
	RSAKey privateKey("RSA_keys\\public.key", "RSA_keys\\private.key");
	string hashName = "SHA1";

	string signature = "MN+PUcjTWw1iKnuT9Bvc6jJFpcaC4ZSipjQGqAzkxBT94sIKuRoS9UjhOGCQvzPs33WGSRMk5Xm6v/ya6rc17pRoXTWEeGqstgYDn+itqaputG6IZdCyF73aJeQbkyz6hruNotkhmcAHQaa+cQt2gMWdOplkcyo32htKepOs1VpVLiu88IY8WiEAToOEQIVQshCpUmBIb7KGREwIAGjrfKIJ+6WnDFYbG61jB70S1NoAvrTRAlkrZsKFNHHXuJ81kdvD/HVnC3SPi59GOSoPICfr73QXXTBknmh04IBSR7nqF9wJDpdPcKgWLxa/l0Jgq5XQQMRIEWlAvPnV+lzeMg==";
	string plainData = "check_card3900iBoxtest_bkc608048151317967320.10.2016 16:33:0061000000101";

	RsaWorker worker;

	// Generate signature
	auto generatedSign = worker.sign(privateKey, hashName, plainData);
	//cout << generatedSign << endl;

	// Verify generated signature
	bool isCorrect = worker.verify(publicKey, "SHA1", plainData, generatedSign);
	cout << "Check signature result: " << boolalpha << isCorrect << endl;

	return 0;
}

