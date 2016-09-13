:: Installs from srtp windows build directory to directory specified on
:: command line


@if "%1"=="" (
	echo "Usage: %~nx0 destdir"
	exit /b 1
) else (
	set destdir=%1
)

@if not exist %destdir% (
   echo %destdir% not found
   exit /b 1
)

@for %%d in (include\srtp.h Debug\srtp.lib Release\srtp.lib) do (
	if not exist "%%d" (
	   echo "%%d not found: are you in the right directory?"
	   exit /b 1
	)
)

mkdir %destdir%\include
mkdir %destdir%\include\srtp2
mkdir %destdir%\lib

copy include\srtp.h include\ekt.h %destdir%\include\srtp2
copy Release\srtp2.lib %destdir%\lib\srtp2.lib
copy Debug\srtp2.lib %destdir%\lib\srtp2d.lib
