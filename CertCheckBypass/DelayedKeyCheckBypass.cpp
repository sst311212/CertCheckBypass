#include <Windows.h>
#include <PIHeaders.h>
#include <Psapi.h>

ASBool CertCheckBypass()
{
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"AcroRd32.dll"), &modInfo, sizeof(modInfo));
	
	for (size_t i = 0; i < modInfo.SizeOfImage; i++) {
		PBYTE pAddress = (PBYTE)modInfo.lpBaseOfDll + i;
		// FE C8 F6 D8 59 1A C0
		if (memcmp(pAddress, "\xFE\xC8\xF6\xD8\x59\x1A\xC0", 7) == 0) {
			WriteProcessMemory(GetCurrentProcess(), pAddress + 5, "\x30", 1, NULL);
			return true;
		}
	}

	return false;
}

ACCB1 ASBool ACCB2 PluginExportHFTs(void)
{
	return true;
}

ACCB1 ASBool ACCB2 PluginImportReplaceAndRegister(void)
{
	return true;
}

ACCB1 ASBool ACCB2 PluginInit(void)
{
	return CertCheckBypass();
}

ACCB1 ASBool ACCB2 PluginUnload(void)
{
	return true;
}

ACCB1 ASBool ACCB2 PIHandshake(ASUns32 handshakeVersion, void *handshakesData)
{
	if (handshakeVersion == HANDSHAKE_V0200) {
		PIHandshakeData_V0200 *hsData = (PIHandshakeData_V0200 *)handshakesData;
		hsData->extensionName = ASAtomFromString("ADBE:CertCheckBypass");
		hsData->exportHFTsCallback = &PluginExportHFTs;
		hsData->importReplaceAndRegisterCallback = &PluginImportReplaceAndRegister;
		hsData->initCallback = &PluginInit;
		hsData->unloadCallback = &PluginUnload;
		return true;
	}
	return false;
}
