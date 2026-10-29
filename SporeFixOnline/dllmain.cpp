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
// Local Variables
//

static const char l_Certificate[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIEyjCCA7KgAwIBAgIJAKwbv3PJfRclMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD\n"
	"VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEVMBMGA1UEBxMMUmVkd29vZCBD\n"
	"aXR5MR4wHAYDVQQKExVFbGVjdHJvbmljIEFydHMsIEluYy4xGzAZBgNVBAsTEkVB\n"
	"IE9ubGluZS9Qb2dvLmNvbTEmMCQGCSqGSIb3DQEJARYXd3d0c28tc3NsLWFkbWlu\n"
	"c0BlYS5jb20wHhcNMjMwOTIxMTkyMzUzWhcNMzMwOTE4MTkyMzUzWjCBnjELMAkG\n"
	"A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFTATBgNVBAcTDFJlZHdvb2Qg\n"
	"Q2l0eTEeMBwGA1UEChMVRWxlY3Ryb25pYyBBcnRzLCBJbmMuMRswGQYDVQQLExJF\n"
	"QSBPbmxpbmUvUG9nby5jb20xJjAkBgkqhkiG9w0BCQEWF3d3dHNvLXNzbC1hZG1p\n"
	"bnNAZWEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzeZCFIBQ\n"
	"BLIRn7acDPDx1LzGnrYJwaBT7CRRye2aXsWGjbcbsyAWcnUYmi7DCz9UZ1G5uOhb\n"
	"MJfwjYJB2fyHqStx6VNTbstvsaNYF29oaoNWjFnM/i8h+DXN52+/CwHkBSPICJ2l\n"
	"joNrgLlRKXDxLVf9Ntw9xhlEPlT0U9EA13KEeIRy6pSbvW45FhDCYBMTRE12O89e\n"
	"fOiXrm5H/SY0eZPdPv8V014tlaf9CyMQyHkMxcNFqN6sH3fNyzHllGXauKzTE3Mo\n"
	"hEV32booDBvsylt9ssHcvzDbhsshW+EW+VyNz6oa7JHG8AiUXRm2LIC7c3PU0B8s\n"
	"2Z+/QBspNadzIQIDAQABo4IBBzCCAQMwHQYDVR0OBBYEFN5ChyoL2UQvg6OMaSR6\n"
	"rni2QU79MIHTBgNVHSMEgcswgciAFN5ChyoL2UQvg6OMaSR6rni2QU79oYGkpIGh\n"
	"MIGeMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEVMBMGA1UEBxMM\n"
	"UmVkd29vZCBDaXR5MR4wHAYDVQQKExVFbGVjdHJvbmljIEFydHMsIEluYy4xGzAZ\n"
	"BgNVBAsTEkVBIE9ubGluZS9Qb2dvLmNvbTEmMCQGCSqGSIb3DQEJARYXd3d0c28t\n"
	"c3NsLWFkbWluc0BlYS5jb22CCQCsG79zyX0XJTAMBgNVHRMEBTADAQH/MA0GCSqG\n"
	"SIb3DQEBCwUAA4IBAQAduVEhOccIWE/mnfBA9me5SAu+t6T/nSc73a8aRrqzH3GO\n"
	"Pzr3ivO/NRe4qUaU0H9LRjVD3fu9zqf9AKJ6TZoPxh31OHNbsZ0QEat4R0Jp5SRc\n"
	"vXV7Wvyp9+ATwp4qVG8CcbKKQaXNGSoFEjC2fo3cUSOASw2fkBItmA4As9dL3dnR\n"
	"TSR3MVpBUJHO4rlAdcbPmHos+omu16ZwxDK0BQADscLr+8U5v1fjc3qMm0HoHOPB\n"
	"Y1o/2LbhJyEQop3xExykLshfJKk+nRg2uL97me6dwEKOGYwsNw3nCpwYrOthHkOh\n"
	"v6GKCq84T4OWUovHW50/UXE3I5Gx3VExLcRLWaKe\n"
	"-----END CERTIFICATE-----\n";

//
// Detoured Functions
//

class CertStream
{
public:
	int _padding_;
	char* mpBuffer;
	uint32_t mnBufSize;
	uint32_t mnPosition;
	// cRandomMaxSequence mMaxSequence
};

member_detour(CertStreamReadDetour, CertStream, int(void* buffer, const int size))
{
	int detoured(void* buffer, int size)
	{
		if ((this->mnPosition + size) >= sizeof(l_Certificate))
		{
			return -1;
		}

		for (int i = 0; i < size; i++)
		{
			((char*)buffer)[i] = l_Certificate[this->mnPosition++];
		}

		return size;
	}
};

//
// Exported Functions
//

void AttachDetours()
{ 
	CertStreamReadDetour::attach(Address(ModAPI::ChooseAddress(0x007c8040, 0x007c79b0)));
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

