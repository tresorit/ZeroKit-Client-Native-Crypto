# ZeroKit client native cryptographic library
[![Build Status](https://travis-ci.org/tresorit/ZeroKit-Client-Native-Crypto.svg?branch=master)](https://travis-ci.org/tresorit/ZeroKit-Client-Native-Crypto)

This library provides native cryptographic primitives for ZeroKit clients,
utilizing OpenSSL's platform-specific optimized assembly implementations where
possible.
Currently supported platforms are iOS (arm, arm64, x86, x64) and Android
(arm, arm64, x86).

## Building

### Prerequisites
 - git
 - GNU make
 - Perl 5
 - Android NDK (Android)
 - Xcode (iOS)

Clone the repository and its submodules:
`git clone https://github.com/tresorit/ZeroKit-Client-Native-Crypto.git --recursive`

#### Android
Generate toolchains for the desired platforms:
```
 $ cd /path/to/ndk/
 $ build/tools/make_standalone_toolchain.py --arch arm --api 14 --stl libc++ --install-dir /path/to/toolchain/tc-arm
 $ build/tools/make_standalone_toolchain.py --arch arm64 --api 21 --stl libc++ --install-dir /path/to/toolchain/tc-arm64
 $ build/tools/make_standalone_toolchain.py --arch x86 --api 14 --stl libc++ --install-dir /path/to/toolchain/tc-x86
```
The library can be built for multiple platforms from the same source dir
by specifying multiple out dirs.
The result will be `libZeroKitClientNative.so` (the stripped, dynamically
linked library) and `libZeroKitClientNative.so.debug` (the debug symbols
for the library) in every out dir.

```
 $ cd /path/to/zerokitclientnative/
 $ make TARGET_OS=android TARGET_CPU=arm ANDROID_TOOLCHAIN_PATH_ARM=/path/to/toolchain/tc-arm OUTDIR=out/arm -j5
 $ make TARGET_OS=android TARGET_CPU=arm64 ANDROID_TOOLCHAIN_PATH_ARM64=/path/to/toolchain/tc-arm64 OUTDIR=out/arm64 -j5
 $ make TARGET_OS=android TARGET_CPU=x86 ANDROID_TOOLCHAIN_PATH_X86=/path/to/toolchain/tc-x86 OUTDIR=out/x86 -j5
```

#### iOS
The library can be built for multiple platforms from the same source dir
by specifying multiple out dirs.
The result will be `libZeroKitClientNative.a` (statically linked archive of
the required object files) in every out dir.

```
 $ cd /path/to/zerokitclientnative/
 $ make TARGET_OS=ios TARGET_CPU=arm OUTDIR=out/arm -j5
 $ make TARGET_OS=ios TARGET_CPU=arm64 OUTDIR=out/arm64 -j5
 $ make TARGET_OS=ios TARGET_CPU=x86 OUTDIR=out/x86 -j5
 $ make TARGET_OS=ios TARGET_CPU=x64 OUTDIR=out/x64 -j5
```
## Changelog
See the [CHANGELOG.md](./CHANGELOG.md) file.

## Contact us
Do you have any questions? [Contact us](mailto:zerokit@tresorit.com) (zerokit@tresorit.com)

## License
See the [LICENSE.txt](./LICENSE.txt) file.
