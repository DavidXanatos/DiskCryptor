mkdir .\Release

mkdir .\Release\ia32
copy ..\DCrypt\Bin\Release_i386\dccon.exe .\Release\ia32\
copy ..\DCrypt\Bin\Release_i386\dcinst.exe .\Release\ia32\
copy ..\DCrypt\Bin\Release_i386\dcrypt.exe .\Release\ia32\
copy ..\DCrypt\Bin\Build_i386\dcrypt.sys .\Release\ia32\
copy ..\DCrypt\Bin\Release_i386\dcapi.dll .\Release\ia32\
copy ..\DCrypt\Bin\Release_i386\dcrypt.pdb .\Release\ia32\
copy ..\DCrypt\Bin\Build_i386\shim_ia32.zip .\Release\ia32\

mkdir .\Release\x64
copy ..\DCrypt\Bin\Release_amd64\dccon.exe .\Release\x64\
copy ..\DCrypt\Bin\Release_amd64\dcinst.exe .\Release\x64\
copy ..\DCrypt\Bin\Release_amd64\dcrypt.exe .\Release\x64\
copy ..\DCrypt\Bin\Build_amd64\dcrypt.sys .\Release\x64\
copy ..\DCrypt\Bin\Release_amd64\dcapi.dll .\Release\x64\
copy ..\DCrypt\Bin\Release_amd64\dcrypt.pdb .\Release\x64\
copy ..\DCrypt\Bin\Build_amd64\shim_x64.zip .\Release\x64\

pause