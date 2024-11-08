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
        void* x509_cert = STATIC_CALL(Address(ModAPI::ChooseAddress(0x0117db60, 0x0117b3e0)), void*, void*, ssl);
        if (x509_cert == nullptr)
        {
            App::ConsolePrintF("SporeFixOnline: SSL_get_peer_certificate() failed!");
            goto out;
        }

        // extract encoded x509
        // x509_cert_len = i2d_X509(x509_cert, &x509_cert_buf);
        x509_cert_len = STATIC_CALL(Address(ModAPI::ChooseAddress(0x0117f700, 0x0117cf80)), int, Args(void*, unsigned char**), Args(x509_cert, &x509_cert_buf));
        if (x509_cert_len < 0)
        {
            App::ConsolePrintF("SporeFixOnline: i2d_X509() failed!");
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
            App::ConsolePrintF("SporeFixOnline: CertCreateContext() failed!");
            goto out;
        }

        // retrieve hash of PCCERT_CONTEXT
        BYTE win32_cert_hash[20];
        DWORD win32_cert_hash_len = 20;
        ret = CertGetCertificateContextProperty(cert_ctx, CERT_HASH_PROP_ID,
            win32_cert_hash, &win32_cert_hash_len);
        if (!ret)
        {
            App::ConsolePrintF("SporeFixOnline: CertGetCertificateContextProperty() failed!");
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
            App::ConsolePrintF("SporeFixOnline: certificate hash NOT matched!");
            for (int i = 0; i < 20; i += 4)
            {
                App::ConsolePrintF("SporeFixOnline: certificate hash: 0x%02X 0x%02X 0x%02X 0x%02X", win32_cert_hash[i], win32_cert_hash[i+1], win32_cert_hash[i+2], win32_cert_hash[i+3]);
            }
        }

    out:
        if (x509_cert != nullptr)
        {
            // X509_free(x509_cert);
            STATIC_CALL(Address(ModAPI::ChooseAddress(0x0117f730, 0x0117cfb0)), void, void*, x509_cert);
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

void Initialize()
{
	// This method is executed when the game starts, before the user interface is shown
	// Here you can do things such as:
	//  - Add new cheats
	//  - Add new simulator classes
	//  - Add new game modes
	//  - Add new space tools
	//  - Change materials
}

void Dispose()
{
	// This method is called when the game is closing
}

void AttachDetours()
{ 
	// Call the attach() method on any detours you want to add
	// For example: cViewer_SetRenderType_detour::attach(GetAddress(cViewer, SetRenderType));

    SSL_CTX_set_verify::attach(Address(ModAPI::ChooseAddress(0x0117e2b0, 0x0117bb30)));
    NetSSLVerifyConnection::attach(Address(ModAPI::ChooseAddress(0x0094f080, 0x0094eb60)));
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
		ModAPI::AddPostInitFunction(Initialize);
		ModAPI::AddDisposeFunction(Dispose);

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

