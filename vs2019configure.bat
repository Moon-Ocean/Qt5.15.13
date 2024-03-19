@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

if not exist buildDir (
    mkdir buildDir
    if errorlevel 1 (
        echo Failed to create buildDir.
    ) else (
        echo buildDir created successfully.
    )
) else (
    echo buildDir already exists.
)

pushd buildDir

..\configure -prefix D:\Qt\Qt5.15.13 -opensource -confirm-license -qt-sqlite -qt-pcre -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype -qt-harfbuzz -opengl dynamic -skip qtwebengine -openssl-runtime OPENSSL_PREFIX="D:\OpenSSL-Win64" -ssl -nomake tests -nomake examples -mp -debug-and-release -optimize-size -strip 

popd
