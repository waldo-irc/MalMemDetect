#pragma once
std::string DetectHollowingAndHooks(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    MODULEINFO lpmodinfo;
    DWORD cb = 1024;
    std::string dllMonitor = "NULL";

    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get a list of all the modules in this process.
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (K32GetModuleFileNameExA(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(char)))
            {
                // Print the module name and handle value.
                printf(TEXT("%s (%p)\n"), szModName, hMods[i]);
                CHAR* log = (CHAR*)malloc(256);
                snprintf(log, 255, TEXT("%s (%p)\n"), szModName, hMods[i]);
                Log(&log);
                free(log);
                // Get file Bytes
                FILE* pFile;
                long lSize;
                //SIZE_T lSize;
                BYTE* buffer;
                size_t result;
                pFile = fopen(szModName, "rb");
                // obtain file size:
                fseek(pFile, 0, SEEK_END);
                lSize = ftell(pFile);
                rewind(pFile);
                // allocate memory to contain the whole file:
                buffer = (BYTE*)malloc(sizeof(BYTE) * lSize);
                // copy the file into the buffer:
                result = fread(buffer, 1, lSize, pFile);
                fclose(pFile);

                // Get memory Bytes
                //GetModuleInformation(hProcess, hMods[i], &lpmodinfo, cb);
                BYTE* buff;
                buff = (BYTE*)malloc(sizeof(BYTE) * lSize);
                _ReadProcessMemory(hProcess, hMods[i], buff, lSize, NULL);

                PIMAGE_NT_HEADERS64 NtHeader = ImageNtHeader(buff);
                PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
                WORD NumSections = NtHeader->FileHeader.NumberOfSections;
                for (WORD i = 0; i < NumSections; i++)
                {
                    std::string secName(reinterpret_cast<char const*>(Section->Name), 5);
                    // Check if the memory is executable
                    if (secName.find(".text") != std::string::npos) {
                        break;
                    }
                    Section++; // If not executable check next section
                }

                float inconsistencies = 0;
                int encodedOpcode = 0;
                for (int i = 0; i < Section->PointerToRawData; i++) {
                    /* the whole file is now loaded in the memory buffer. */
                    // terminate

                    if (buff[i] != buffer[i]) {
                        if (encodedOpcode < 4) {
                            encodedOpcode++;
                        }
                        else {
                            inconsistencies++;
                        }
                    }
                }

                // The first is the offset from the file on disk
                // The second is the offset to .txt from memory
                LPBYTE txtSectionFile = buffer + Section->PointerToRawData;
                LPBYTE txtSectionMem = buff + Section->VirtualAddress;
                for (int i = 0; i < Section->SizeOfRawData; i++) {
                    /* the whole file is now loaded in the memory buffer. */
                    // terminate

                    //printf("%x\n\n", buff[i]);
                    if ((char*)txtSectionFile[i] != (char*)txtSectionMem[i]) {
                        inconsistencies++;
                    }
                }

                float icPercent = (inconsistencies / (Section->SizeOfRawData + Section->PointerToRawData)) * 100;
                if (inconsistencies > 5) {
                    printf("Found more than 5 bytes altered, there's potentially hooks here: %s Bytes Altered: %f\n", szModName, inconsistencies);
                    CHAR* log = (CHAR*)malloc(256);
                    snprintf(log, 255, "Found more than 5 bytes altered, there's potentially hooks here: %s Bytes Altered: %f\n", szModName, inconsistencies);
                    LogDetected(&log);
                    free(log);
                }
                if (inconsistencies > 10000) {
                    printf("FOUND DLL HOLLOW.\nNOW MONITORING: %s with %f changes found. %f%% Overall\n\n", szModName, inconsistencies, icPercent);
                    CHAR* log = (CHAR*)malloc(256);
                    snprintf(log, 255, "FOUND DLL HOLLOW.\nNOW MONITORING: %s with %f changes found. %f%% Overall\n\n", szModName, inconsistencies, icPercent);
                    LogDetected(&log);
                    free(log);
                    std::string moduleName(szModName, sizeof(szModName) / sizeof(char));
                    std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(),
                        [](unsigned char c) { return tolower(c); });
                    dllMonitor = moduleName;
                    break;
                }

                free(buffer);
            }
        }
    }

    // Release the handle to the process.
    CloseHandle(hProcess);
    return dllMonitor;
}