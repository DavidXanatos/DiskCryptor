if not defined WORKSPACE (
   echo WORKSPACE not defined
   goto :eof
)
pushd %WORKSPACE%
build %*
REM build -n 1 %*
popd