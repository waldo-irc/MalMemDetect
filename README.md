# MalMemDetect
Detect strange memory regions and DLLs


Compile as a DLL and inject into a process to identify hollowed DLLs and unmapped memory region calls.


Sleep hook seems to break a few things so I left it in but commented, as well as a few other things that are left more as "Demos" and commented out.


Results by default will output to a file in C:\ drive.


## Sample Output

```
Suspicious Malloc() from thread with id:12780 LPVOID:000002C38082B1D0 Heap Handle:000002C380790000 Size: 32
Suspicious InternetConnectA() from thread with id:12780 Name: 10.0.0.129 Creds: (null)[(null)]
Suspicious Malloc() from thread with id:12780 LPVOID:000002C3807EBA20 Heap Handle:000002C380790000 Size: 24
Suspicious Malloc() from thread with id:12780 LPVOID:000002C383988550 Heap Handle:000002C380790000 Size: 27648
Suspicious Malloc() from thread with id:12780 LPVOID:000002C382882650 Heap Handle:000002C380790000 Size: 5543
Suspicious Malloc() from thread with id:12780 LPVOID:000002C38082B1D0 Heap Handle:000002C380790000 Size: 32
Suspicious InternetConnectA() from thread with id:12780 Name: 10.0.0.129 Creds: (null)[(null)]
Suspicious Malloc() from thread with id:12780 LPVOID:000002C3807EB400 Heap Handle:000002C380790000 Size: 24
Suspicious Malloc() from thread with id:12780 LPVOID:000002C383988550 Heap Handle:000002C380790000 Size: 27648
Suspicious Malloc() from thread with id:12780 LPVOID:000002C382882650 Heap Handle:000002C380790000 Size: 5543
Suspicious Malloc() from thread with id:12780 LPVOID:000002C38082B1D0 Heap Handle:000002C380790000 Size: 32
Suspicious InternetConnectA() from thread with id:12780 Name: 10.0.0.129 Creds: (null)[(null)]
Suspicious Malloc() from thread with id:12780 LPVOID:000002C3807EB940 Heap Handle:000002C380790000 Size: 24
Suspicious Malloc() from thread with id:12780 LPVOID:000002C383988550 Heap Handle:000002C380790000 Size: 27648
Suspicious Malloc() from thread with id:12780 LPVOID:000002C382882650 Heap Handle:000002C380790000 Size: 5543
Suspicious Malloc() from thread with id:12780 LPVOID:000002C38082B1D0 Heap Handle:000002C380790000 Size: 32
Suspicious InternetConnectA() from thread with id:12780 Name: 10.0.0.129 Creds: (null)[(null)]
```

```
Found more than 5 bytes altered, there's potentially hooks here: C:\Windows\system32\xpsservices.dll Bytes Altered: 307094.000000
FOUND DLL HOLLOW.
NOW MONITORING: C:\Windows\system32\xpsservices.dll with 307094.000000 changes found. 15.442662% Overall

Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9D0EA40 Heap Handle:000001DCB9C80000  Size: 32
Suspicious InternetConnectA() from module with name: c:\windows\system32\xpsservices.dll, Name: 10.0.0.129 Creds: (null)[(null)]
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9CD3C20 Heap Handle:000001DCB9C80000  Size: 24
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9D143F0 Heap Handle:000001DCB9C80000  Size: 27648
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCBBE52650 Heap Handle:000001DCB9C80000  Size: 5543
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9D0EA40 Heap Handle:000001DCB9C80000  Size: 32
Suspicious InternetConnectA() from module with name: c:\windows\system32\xpsservices.dll, Name: 10.0.0.129 Creds: (null)[(null)]
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9CD3AA0 Heap Handle:000001DCB9C80000  Size: 24
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9D143F0 Heap Handle:000001DCB9C80000  Size: 27648
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCBBE52650 Heap Handle:000001DCB9C80000  Size: 5543
Suspicious Malloc() from module with name:c:\windows\system32\xpsservices.dll LPVOID:000001DCB9D0EA40 Heap Handle:000001DCB9C80000  Size: 32
Suspicious InternetConnectA() from module with name: c:\windows\system32\xpsservices.dll, Name: 10.0.0.129 Creds: (null)[(null)]
```
