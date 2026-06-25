set -e
if [ -d buildUniversal ]; then
    echo "buildUniversal 文件夹已经存在，继续编译会删除旧的编译文件。"
    read -p "是否继续？[y/N] " answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            rm -rf buildUniversal
            ;;
        *)
            echo "已取消编译。"
            exit 0
            ;;
    esac
fi

mkdir buildUniversal && cd buildUniversal
../configure -debug-and-release -force-debug-info -separate-debug-info -prefix ~/code/lib/Qt/universal -nomake examples -nomake tests QMAKE_APPLE_DEVICE_ARCHS="x86_64 arm64" QMAKE_MACOSX_DEPLOYMENT_TARGET=10.14 -opensource -confirm-license -skip qt3d -skip qtwebengine -skip qtlocation -openssl-runtime -no-securetransport -I ~/code/lib/openssl/universal/include -L ~/code/lib/openssl/universal/lib
make -j8 && make install
build_result=$?

if [ $build_result -ne 0 ]; then
    exit $build_result
fi

cd ..

read -p "编译完成，是否上传调试符号？[y/N] " upload_answer
case "$upload_answer" in
    [Yy]|[Yy][Ee][Ss])
        ./upload_debug_symbols.py
        ;;
    *)
        echo "已跳过上传调试符号。"
        ;;
esac
