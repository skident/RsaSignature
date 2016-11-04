#pragma once

#include <string>
#include <Poco/Crypto/RSAKey.h>

class RsaWorker
{
public:
	typedef std::string Signature;

	RsaWorker(void);
	~RsaWorker(void);

	typedef std::string base64encode;

	bool verify(const Poco::Crypto::RSAKey& publicKey, const std::string &hashName, const std::string plainData, const base64encode& signature);

	
	Signature sign(const Poco::Crypto::RSAKey& privateKey, const std::string &hashName, const std::string plainData);

private:
	class DataDigestEngine;
	
	std::string base64Decode(const std::string& data);
	std::string base64Encode(const std::vector<unsigned char>& data);
};

//
//
//class SignatureVerifier: public Poco::Crypto::RSADigestEngine
//{
//private:
//	class DataDigestEngine : public Poco::DigestEngine
//	{
//		Digest m_digest;
//	public:
//		//! Returns the length of the digest in bytes.
//		virtual std::size_t digestLength() const override
//		{
//			return m_digest.size();
//		}
//
//		//! Resets the engine so that a new
//		//! digest can be computed.
//		virtual void reset() override
//		{
//			m_digest.clear();
//		}
//		
//		
//		virtual const Digest& digest() override
//		{
//			return m_digest;
//		}
//
//	protected:
//		virtual void updateImpl(const void* data, std::size_t length) override
//		{
//			const char* ptr = static_cast<const char*>(data);
//			m_digest.assign(ptr, ptr+length);
//		}
//
//	};
//
//	std::string base64Decode(const std::string& data);
//
//public:
//	typedef std::string base64encode;
//
//	SignatureVerifier(const Poco::Crypto::RSAKey& key, const std::string &name);
//	~SignatureVerifier(void);
//
//	bool verify(const base64encode& signature, const std::string data);
//};