copy /y %1 %2

REM %~dp0..\..\DiskCryptor\DCrypt\tools\llvm\llvm-objcopy.exe --add-section .sbat="%~dp0SecureBoot\sbat.csv" --set-section-flags .sbat=contents,alloc,load,readonly,data "%1" "%2"
REM signtool sign /fd SHA256 /a /f "%~dp0SecureBoot\MOK.pfx" /t http://timestamp.digicert.com "%2"
