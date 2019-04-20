@echo off
pushd "%~dp0"

del *.ncb /S /Q
del *.sdf /S /Q
del *.suo /S /Q /F /A:H
del *.user /S /Q

del bartpe\*.dll /Q
del bartpe\*.exe /Q
del bartpe\*.sys /Q

rmdir ipch /S /Q

rmdir Bin\boot /S /Q
rmdir Bin\Debug_i386 /S /Q
rmdir Bin\Release_i386 /S /Q
rmdir Bin\Debug_amd64 /S /Q
rmdir Bin\Release_amd64 /S /Q

del Bin\dcrypt_setup.exe /Q

popd