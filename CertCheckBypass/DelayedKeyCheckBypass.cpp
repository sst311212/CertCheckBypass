#include <Windows.h>
#include <PIHeaders.h>
#include <Psapi.h>

ASBool CertCheckBypass()
{
	MODULEINFO modInfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"AcroRd32.dll"), &modInfo, sizeof(modInfo));
	
	for (size_t i = 0; i < modInfo.SizeOfImage; i++) {
		PBYTE pAddress = (PBYTE)modInfo.lpBaseOfDll + i;
		// 59 0F B7 F8 83 4D FC FF
		if (memcmp(pAddress, "\x59\x0F\xB7\xF8\x83\x4D\xFC\xFF", 8) == 0) {
			WriteProcessMemory(GetCurrentProcess(), pAddress + 1, "\x33\xFF\x47", 3, NULL);
			return true;
		}
		// 59 0F B7 F0 8D 4D F0 E8 ?? ?? ?? ?? 66 8B C6
		if (memcmp(pAddress, "\x59\x0F\xB7\xF0\x8D\x4D\xF0\xE8", 8) == 0) {
			if (memcmp(pAddress + 12, "\x66\x8B\xC6", 3) == 0) {
				WriteProcessMemory(GetCurrentProcess(), pAddress + 1, "\x31\xF6\x46", 3, NULL);
				return true;
			}
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