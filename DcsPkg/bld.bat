if not defined WORKSPACE (
   echo WORKSPACE not defined
   goto :eof
)
pushd %WORKSPACE%
build %*
popd