#include "RsaWorker.hpp"
#include <Poco/DigestEngine.h>
#include <Poco/Crypto/RSADigestEngine.h>
#include <Poco/Base64Decoder.h>
#include <Poco/Base64Encoder.h>
#include <sstream>
#include <iterator>


using namespace std;

class RsaWorker::DataDigestEngine : public Poco::DigestEngine
{
	Digest m_digest;
public:
	//! Returns the length of the digest in bytes.
	virtual size_t digestLength() const override
	{
		return m_digest.size();
	}

	//! Resets the engine so that a new
	//! digest can be computed.
	virtual void reset() override
	{
		m_digest.clear();
	}
		
		
	virtual const Digest& digest() override
	{
		return m_digest;
	}

protected:
	virtual void updateImpl(const void* data, size_t length) override
	{
		const char* ptr = static_cast<const char*>(data);
		m_digest.assign(ptr, ptr+length);
	}

};

/////////////////////////////////////


RsaWorker::RsaWorker(void)
{
}


RsaWorker::~RsaWorker(void)
{
}

bool RsaWorker::verify(const Poco::Crypto::RSAKey& publicKey, const string& hashName, const string plainData, const base64encode& signature)
{
	DataDigestEngine signatureEngine;
	signatureEngine.update(base64Decode(signature)); // decode signature from Base64

	Poco::Crypto::RSADigestEngine digest(publicKey, hashName);
	digest.update(plainData);
	bool isCorrect = digest.verify(signatureEngine.digest());
	return isCorrect;
}

RsaWorker::Signature RsaWorker::sign(const Poco::Crypto::RSAKey& privateKey, const string& hashName, const string plainData)
{
	Poco::Crypto::RSADigestEngine digest(privateKey, hashName);
	digest.update(plainData);
	auto signature = digest.signature();
	const auto& base64Sign = base64Encode(signature);
	return base64Sign;
}

string RsaWorker::base64Decode(const string& data)
{
	stringstream istr;
	istr << data;

	ostringstream ostr;
	Poco::Base64Decoder decoder(istr);
	copy(istreambuf_iterator<char>(decoder),
		        istreambuf_iterator<char>(),
		        ostreambuf_iterator<char>(ostr));

	return ostr.str();
}

string RsaWorker::base64Encode(const vector<unsigned char>& data)
{
	ostringstream ss;
	Poco::Base64Encoder encoder(ss);
	copy(data.begin(), data.end(), ostream_iterator<unsigned char>(encoder));
	encoder.close();

	return ss.str();
}
