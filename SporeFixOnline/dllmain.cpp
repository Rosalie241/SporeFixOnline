//
// SporeFixOnline - https://github.com/Rosalie241/SporeFixOnline
//  Copyright (C) 2021 Rosalie Wanders <rosalie@mailbox.org>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License version 3.
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <https://www.gnu.org/licenses/>.
//

// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <Spore\BasicIncludes.h>

#include <string>
#include <map>

//
// Local Variables
//

uint32_t baseAddress = 0x0;

//
// Helper functions
//

static void DisplayError(const char* fmt, ...)
{
	char buf[200];

	va_list args;
	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);

	MessageBoxA(NULL, buf, "SporeFixOnline", MB_OK | MB_ICONERROR);
}

//
// Detoured Functions
//

static_detour(SSL_CTX_set_verify, void(void*, int, void*))
{
    void detoured(void* ssl, int mode, void* callback)
    {
        // force SSL_VERIFY_NONE to disable verifying CA chain,
        // this isn't that insecure because we force a hash match
        // in NetSSLVerifyConnection anyways
        // TODO: figure out how Spore sets the CA certificates
        return original_function(ssl, 0x00, callback);
    }
};

static_detour(RegisterHostFromAppProperties, void(uint32_t, const char*))
{
    void detoured(uint32_t id, const char* host)
    {
        if (id == 0x5384c3f)
        {
            // hack to override pollinator URL
            return original_function(0x5384c40, "pollinator.spore.com");
        }
        else if (id == 0x53dd8c2)
        {
            return original_function(id, "community.spore.com");
        }

        return original_function(id, host);
    }
};

static_detour(RegisterURL, void(uint32_t, uint32_t, const char*))
{
    void detoured(uint32_t id1, uint32_t id2, const char* url)
    {
        const std::map<std::string, std::string> overrideUrlMap =
        {
            { "/community/mvj/community_page", "/community/assetBrowser/home" },
        };

        // hack to override pollinator URL
        if (id2 == 0x5384c3f)
            id2 = 0x5384c40;

        for (const auto& pair : overrideUrlMap)
        {
            if (pair.first == url)
            {
                return original_function(id1, id2, pair.second.c_str());
            }
        }

        return original_function(id1, id2, url);
    }
};

static_detour(NetSSLVerifyConnection, int(void*, char*)) {
    int detoured(void* ssl, char* servername)
    {
        // openssl variables
        unsigned char* x509_cert_buf = nullptr;
        int x509_cert_len = 0;

        // win32 crypt variables
        PCCERT_CONTEXT cert_ctx = nullptr;

        bool ret = false;

        // retrieve current certificate
        // X509* x509_cert = SSL_get_peer_certificate(ssl);
        void* x509_cert = STATIC_CALL(Address(0x011a05d0), void*, void*, ssl);
        if (x509_cert == nullptr)
        {
            DisplayError("SporeFixOnline: SSL_get_peer_certificate() failed!");
            goto out;
        }

        // extract encoded x509
        // x509_cert_len = i2d_X509(x509_cert, &x509_cert_buf);
        x509_cert_len = STATIC_CALL(Address(0x011a2dc0), int, Args(void*, unsigned char**), Args(x509_cert, &x509_cert_buf));
        if (x509_cert_len < 0)
        {
            DisplayError("SporeFixOnline: i2d_X509() failed!");
            goto out;
        }

        // convert encoded x509 to PCCERT_CONTEXT
        cert_ctx = (PCCERT_CONTEXT)CertCreateContext(CERT_STORE_CERTIFICATE_CONTEXT,
            X509_ASN_ENCODING,
            x509_cert_buf,
            x509_cert_len,
            0,
            nullptr);
        if (cert_ctx == nullptr)
        {
            DisplayError("SporeFixOnline: CertCreateContext() failed!");
            goto out;
        }

        // retrieve hash of PCCERT_CONTEXT
        BYTE win32_cert_hash[20];
        DWORD win32_cert_hash_len = 20;
        ret = CertGetCertificateContextProperty(cert_ctx, CERT_HASH_PROP_ID,
            win32_cert_hash, &win32_cert_hash_len);
        if (!ret)
        {
            DisplayError("SporeFixOnline: CertGetCertificateContextProperty() failed!");
            goto out;
        }

        // sadly the official servers
        // don't have valid certificates
        // so return success when
        // we encounter one of these
        BYTE certificateHashes[][20] =
        {
            { // pollinator.spore.com
                0x26, 0x95, 0x77, 0x65,
                0x5C, 0xDD, 0x70, 0x98,
                0x74, 0x29, 0x72, 0x47,
                0x99, 0xFB, 0xFF, 0x57,
                0x38, 0xC7, 0x88, 0x74
            },
            { // community.spore.com
                0xA9, 0x9B, 0xE0, 0xF2,
                0xED, 0xC0, 0x7D, 0xA0,
                0x7D, 0x9B, 0xC0, 0x84,
                0x20, 0xC6, 0x3D, 0xF0,
                0x3B, 0xD6, 0x9C, 0xC2
            }
        };

        // loop over each certificate
        // and check if the current hash matches
        for (int i = 0; i < ARRAYSIZE(certificateHashes); i++)
        {
            if (memcmp(win32_cert_hash, certificateHashes[i], 20) == 0)
            {
                ret = true;
                break;
            }
        }

        if (!ret)
        {
            DisplayError("SporeFixOnline: certificate hash NOT matched!");
        }

    out:
        if (x509_cert != nullptr)
        {
            // X509_free(x509_cert);
            STATIC_CALL(Address(0x011a2df0), void, void*, x509_cert);
        }
        if (cert_ctx != nullptr)
        {
            CertFreeCertificateContext(cert_ctx);
        }

        // 0 = success
        // 1 = failure
        return ret ? 0 : 1;
    }
};

//
// Exported Functions
//

void AttachDetours()
{ 
    baseAddress = (uint32_t)GetModuleHandle(NULL);

    SSL_CTX_set_verify::attach(Address(0x011a1170));
    NetSSLVerifyConnection::attach(Address(0x01146ab0));
    RegisterHostFromAppProperties::attach(Address(0x00da3a00));
    RegisterURL::attach(Address(0x00da3a60));
}

// The game calls this function but ignores the result, so just return E_FAIL.
extern "C" HRESULT WINAPI DirectInput8Create(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN)
{
    return E_FAIL;
}


// Generally, you don't need to touch any code here
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		PrepareDetours(hModule);
		AttachDetours();
		CommitDetours();
		break;

	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

