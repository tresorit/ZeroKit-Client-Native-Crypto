#
# Copyright (c) 2017, Tresorit Kft.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

ifeq ($(TARGET_OS),)
ifeq ($(TARGET_CPU),)
$(error Missing target. You must specify TARGET_OS and TARGET_CPU)
endif
endif

ifneq ($(TARGET_OS):$(TARGET_CPU),android:arm)
ifneq ($(TARGET_OS):$(TARGET_CPU),android:arm64)
ifneq ($(TARGET_OS):$(TARGET_CPU),android:x86)
ifneq ($(TARGET_OS):$(TARGET_CPU),ios:arm)
ifneq ($(TARGET_OS):$(TARGET_CPU),ios:arm64)
ifneq ($(TARGET_OS):$(TARGET_CPU),ios:x86)
ifneq ($(TARGET_OS):$(TARGET_CPU),ios:x64)
$(error Unsupported target: $(TARGET_OS) on $(TARGET_CPU))
endif
endif
endif
endif
endif
endif
endif

OUTDIR = .

FLAGS = -fstack-protector-strong \
	-g \
	-fvisibility=hidden \
	-ferror-limit=1000 \
	-fstandalone-debug \
	-fcolor-diagnostics \
	-O3 \
	-DNDEBUG \
	$(INC) \
	$(DEFINES)

ifeq ($(TARGET_OS),android)
	TARGET = $(OUTDIR)/libZeroKitClientNative.so

	FLAGS += -fdata-sections \
		-ffunction-sections \
		-D_FILE_OFFSET_BITS=64 \
		-fPIC \
		-pipe \
		-pthread \
		-fno-integrated-as \
		-g3 \
		-gdwarf-3 \
		-ggdb

	LDFLAGS = -fdata-sections \
		-ffunction-sections \
		-fstack-protector-strong \
		-fvisibility=hidden \
		-g \
		-fPIC \
		-pipe \
		-Wl,-z,relro \
		-Wl,-z,now \
		-Wl,-z,noexecstack \
		-Wl,-gc-sections \
		-Wl,--disable-new-dtags \
		-Bdynamic \
		-Wl,--build-id=sha1 \
		-Wl,-z,defs \
		-Wl,-z,nocopyreloc \
		-static-libstdc++ \
		-g3 \
		-gdwarf-3 \
		-ggdb \
		-pthread \
		-Wl,--icf=safe \
		-fuse-ld=gold \
		-lc++_static \
		-lc++abi \
		-landroid_support \
		-latomic

	ifeq ($(TARGET_CPU),arm)
		CC = $(ANDROID_TOOLCHAIN_PATH_ARM)/bin/arm-linux-androideabi-clang
		CXX = $(ANDROID_TOOLCHAIN_PATH_ARM)/bin/arm-linux-androideabi-clang++
		AR = $(ANDROID_TOOLCHAIN_PATH_ARM)/bin/arm-linux-androideabi-ar
		OBJCOPY = $(ANDROID_TOOLCHAIN_PATH_ARM)/bin/arm-linux-androideabi-objcopy
		FLAGS += -march=armv5te \
			-mtune=xscale \
			-msoft-float \
			-marm \
			-target armv5te-none-linux-androideabi
		LDFLAGS += -target armv5te-none-linux-androideabi \
			-lunwind
	else ifeq ($(TARGET_CPU),arm64)
		CC = $(ANDROID_TOOLCHAIN_PATH_ARM64)/bin/aarch64-linux-android-clang
		CXX = $(ANDROID_TOOLCHAIN_PATH_ARM64)/bin/aarch64-linux-android-clang++
		AR = $(ANDROID_TOOLCHAIN_PATH_ARM64)/bin/aarch64-linux-android-ar
		OBJCOPY = $(ANDROID_TOOLCHAIN_PATH_ARM64)/bin/aarch64-linux-android-objcopy
		FLAGS += -target aarch64-none-linux-android
		LDFLAGS += -target aarch64-none-linux-android
	else ifeq ($(TARGET_CPU),x86)
		CC = $(ANDROID_TOOLCHAIN_PATH_X86)/bin/i686-linux-android-clang
		CXX = $(ANDROID_TOOLCHAIN_PATH_X86)/bin/i686-linux-android-clang++
		AR = $(ANDROID_TOOLCHAIN_PATH_X86)/bin/i686-linux-android-ar
		OBJCOPY = $(ANDROID_TOOLCHAIN_PATH_X86)/bin/i686-linux-android-objcopy
		FLAGS += -target i686-none-linux-android
		LDFLAGS += -target i686-none-linux-android
	endif
else ifeq ($(TARGET_OS), ios)
	TARGET = $(OUTDIR)/libZeroKitClientNative.a

	FLAGS += -fembed-bitcode \
		-stdlib=libc++ \
		-miphoneos-version-min=7.0 \
		-D__IPHONE_OS_VERSION_MIN_REQUIRED=70000

	ifeq ($(TARGET_CPU),arm)
		CC = xcrun -sdk iphoneos cc -arch armv7
		CXX = xcrun -sdk iphoneos c++ -arch armv7
		LIBTOOL = xcrun -sdk iphoneos libtool
	else ifeq ($(TARGET_CPU),arm64)
		CC = xcrun -sdk iphoneos cc -arch arm64
		CXX = xcrun -sdk iphoneos c++ -arch arm64
		LIBTOOL = xcrun -sdk iphoneos libtool
	else ifeq ($(TARGET_CPU),x86)
		CC = xcrun -sdk iphonesimulator cc -arch i386
		CXX = xcrun -sdk iphonesimulator c++ -arch i386
		LIBTOOL = xcrun -sdk iphonesimulator libtool
	else ifeq ($(TARGET_CPU),x64)
		CC = xcrun -sdk iphonesimulator cc -arch x86_64
		CXX = xcrun -sdk iphonesimulator c++ -arch x86_64
		LIBTOOL = xcrun -sdk iphonesimulator libtool
	endif
endif

CFLAGS = $(FLAGS) \
	-std=gnu99

CXXFLAGS = $(FLAGS) \
	-std=c++14 \
	-fvisibility-inlines-hidden

AS = $(CC)
ASFLAGS = $(CFLAGS)
LD = $(CXX)

INC = -I. -Iopenssl -Iopenssl/include -Iopenssl/crypto -Iopenssl/crypto/include -Iopenssl/crypto/modes 

DEFINES = -DNO_WINDOWS_BRAINDEATH \
	-DOPENSSL_MIN_API=0x10100000 \
	-DOPENSSL_NO_DES \
	-DOPENSSL_NO_STDIO \
	-DOPENSSL_NO_FP_API

ifeq ($(TARGET_CPU),arm64)
	DEFINES += -DSIXTY_FOUR_BIT_LONG
else ifeq ($(TARGET_CPU),x64)
	DEFINES += -DSIXTY_FOUR_BIT_LONG
else ifeq ($(TARGET_CPU),arm)
	DEFINES += -DBN_LLONG \
		-DTHIRTY_TWO_BIT
else ifeq ($(TARGET_CPU),x86)
	DEFINES += -DBN_LLONG \
		-DTHIRTY_TWO_BIT
endif

HEADERS = openssl/include/openssl/aes.h \
	openssl/include/openssl/asn1.h \
	openssl/include/openssl/asn1_mac.h \
	openssl/include/openssl/asn1t.h \
	openssl/include/openssl/async.h \
	openssl/include/openssl/bio.h \
	openssl/include/openssl/blowfish.h \
	openssl/include/openssl/bn.h \
	openssl/include/openssl/buffer.h \
	openssl/include/openssl/camellia.h \
	openssl/include/openssl/cast.h \
	openssl/include/openssl/cmac.h \
	openssl/include/openssl/cms.h \
	openssl/include/openssl/comp.h \
	openssl/include/openssl/conf_api.h \
	openssl/include/openssl/conf.h \
	openssl/include/openssl/crypto.h \
	openssl/include/openssl/ct.h \
	openssl/include/openssl/__DECC_INCLUDE_EPILOGUE.H \
	openssl/include/openssl/__DECC_INCLUDE_PROLOGUE.H \
	openssl/include/openssl/des.h \
	openssl/include/openssl/dh.h \
	openssl/include/openssl/dsa.h \
	openssl/include/openssl/dtls1.h \
	openssl/include/openssl/ebcdic.h \
	openssl/include/openssl/ecdh.h \
	openssl/include/openssl/ecdsa.h \
	openssl/include/openssl/ec.h \
	openssl/include/openssl/engine.h \
	openssl/include/openssl/e_os2.h \
	openssl/include/openssl/err.h \
	openssl/include/openssl/evp.h \
	openssl/include/openssl/hmac.h \
	openssl/include/openssl/idea.h \
	openssl/include/openssl/kdf.h \
	openssl/include/openssl/lhash.h \
	openssl/include/openssl/md2.h \
	openssl/include/openssl/md4.h \
	openssl/include/openssl/md5.h \
	openssl/include/openssl/mdc2.h \
	openssl/include/openssl/modes.h \
	openssl/include/openssl/objects.h \
	openssl/include/openssl/obj_mac.h \
	openssl/include/openssl/ocsp.h \
	openssl/include/openssl/opensslv.h \
	openssl/include/openssl/ossl_typ.h \
	openssl/include/openssl/pem2.h \
	openssl/include/openssl/pem.h \
	openssl/include/openssl/pkcs12.h \
	openssl/include/openssl/pkcs7.h \
	openssl/include/openssl/rand.h \
	openssl/include/openssl/rc2.h \
	openssl/include/openssl/rc4.h \
	openssl/include/openssl/rc5.h \
	openssl/include/openssl/ripemd.h \
	openssl/include/openssl/rsa.h \
	openssl/include/openssl/safestack.h \
	openssl/include/openssl/seed.h \
	openssl/include/openssl/sha.h \
	openssl/include/openssl/srp.h \
	openssl/include/openssl/srtp.h \
	openssl/include/openssl/ssl2.h \
	openssl/include/openssl/ssl3.h \
	openssl/include/openssl/ssl.h \
	openssl/include/openssl/stack.h \
	openssl/include/openssl/symhacks.h \
	openssl/include/openssl/tls1.h \
	openssl/include/openssl/ts.h \
	openssl/include/openssl/txt_db.h \
	openssl/include/openssl/ui.h \
	openssl/include/openssl/whrlpool.h \
	openssl/include/openssl/x509.h \
	openssl/include/openssl/x509v3.h \
	openssl/include/openssl/x509_vfy.h \
	openssl/crypto/include/internal/asn1_int.h \
	openssl/crypto/include/internal/bn_conf.h.in \
	openssl/crypto/include/internal/bn_int.h \
	openssl/crypto/include/internal/chacha.h \
	openssl/crypto/include/internal/cryptlib.h \
	openssl/crypto/include/internal/cryptlib_int.h \
	openssl/crypto/include/internal/engine.h \
	openssl/crypto/include/internal/evp_int.h \
	openssl/crypto/include/internal/objects.h \
	openssl/crypto/include/internal/rand.h \
	openssl/crypto/include/internal/async.h \
	openssl/crypto/include/internal/bn_dh.h \
	openssl/crypto/include/internal/bn_srp.h \
	openssl/crypto/include/internal/cryptlib.h \
	openssl/crypto/include/internal/dso_conf.h.in \
	openssl/crypto/include/internal/err_int.h \
	openssl/crypto/include/internal/md32_common.h \
	openssl/crypto/include/internal/poly1305.h \
	openssl/crypto/include/internal/x509_int.h \
	openssl/opensslconf.h \
	BigNum.hpp \
	Cipher.hpp \
	Hex.hpp \
	Key.hpp \
	MessageDigest.hpp \
	OpenSSLException.hpp \
	SecureVector.hpp \
	Srp6.hpp \
	ZeroKitClientNative.h

OPENSSL_OBJECTS = openssl/crypto/aes/aes_cbc.o \
	openssl/crypto/aes/aes_cfb.o \
	openssl/crypto/aes/aes_core.o \
	openssl/crypto/aes/aes_ecb.o \
	openssl/crypto/aes/aes_ige.o \
	openssl/crypto/aes/aes_misc.o \
	openssl/crypto/aes/aes_ofb.o \
	openssl/crypto/aes/aes_wrap.o \
	openssl/crypto/asn1/a_bitstr.o \
	openssl/crypto/asn1/a_d2i_fp.o \
	openssl/crypto/asn1/a_digest.o \
	openssl/crypto/asn1/a_dup.o \
	openssl/crypto/asn1/a_gentm.o \
	openssl/crypto/asn1/a_i2d_fp.o \
	openssl/crypto/asn1/a_int.o \
	openssl/crypto/asn1/a_mbstr.o \
	openssl/crypto/asn1/a_object.o \
	openssl/crypto/asn1/a_octet.o \
	openssl/crypto/asn1/a_print.o \
	openssl/crypto/asn1/a_sign.o \
	openssl/crypto/asn1/a_strex.o \
	openssl/crypto/asn1/a_strnid.o \
	openssl/crypto/asn1/a_time.o \
	openssl/crypto/asn1/a_type.o \
	openssl/crypto/asn1/a_utctm.o \
	openssl/crypto/asn1/a_utf8.o \
	openssl/crypto/asn1/a_verify.o \
	openssl/crypto/asn1/ameth_lib.o \
	openssl/crypto/asn1/asn1_err.o \
	openssl/crypto/asn1/asn1_gen.o \
	openssl/crypto/asn1/asn1_lib.o \
	openssl/crypto/asn1/asn1_par.o \
	openssl/crypto/asn1/asn_mime.o \
	openssl/crypto/asn1/asn_moid.o \
	openssl/crypto/asn1/asn_mstbl.o \
	openssl/crypto/asn1/asn_pack.o \
	openssl/crypto/asn1/bio_asn1.o \
	openssl/crypto/asn1/bio_ndef.o \
	openssl/crypto/asn1/d2i_pr.o \
	openssl/crypto/asn1/d2i_pu.o \
	openssl/crypto/asn1/evp_asn1.o \
	openssl/crypto/asn1/f_int.o \
	openssl/crypto/asn1/f_string.o \
	openssl/crypto/asn1/i2d_pr.o \
	openssl/crypto/asn1/i2d_pu.o \
	openssl/crypto/asn1/n_pkey.o \
	openssl/crypto/asn1/nsseq.o \
	openssl/crypto/asn1/p5_pbe.o \
	openssl/crypto/asn1/p5_pbev2.o \
	openssl/crypto/asn1/p5_scrypt.o \
	openssl/crypto/asn1/p8_pkey.o \
	openssl/crypto/asn1/t_bitst.o \
	openssl/crypto/asn1/t_pkey.o \
	openssl/crypto/asn1/t_spki.o \
	openssl/crypto/asn1/tasn_dec.o \
	openssl/crypto/asn1/tasn_enc.o \
	openssl/crypto/asn1/tasn_fre.o \
	openssl/crypto/asn1/tasn_new.o \
	openssl/crypto/asn1/tasn_prn.o \
	openssl/crypto/asn1/tasn_scn.o \
	openssl/crypto/asn1/tasn_typ.o \
	openssl/crypto/asn1/tasn_utl.o \
	openssl/crypto/asn1/x_algor.o \
	openssl/crypto/asn1/x_bignum.o \
	openssl/crypto/asn1/x_info.o \
	openssl/crypto/asn1/x_int64.o \
	openssl/crypto/asn1/x_long.o \
	openssl/crypto/asn1/x_pkey.o \
	openssl/crypto/asn1/x_sig.o \
	openssl/crypto/asn1/x_spki.o \
	openssl/crypto/asn1/x_val.o \
	openssl/crypto/async/arch/async_null.o \
	openssl/crypto/async/async.o \
	openssl/crypto/async/async_err.o \
	openssl/crypto/async/async_wait.o \
	openssl/crypto/bio/b_addr.o \
	openssl/crypto/bio/b_dump.o \
	openssl/crypto/bio/b_print.o \
	openssl/crypto/bio/b_sock.o \
	openssl/crypto/bio/b_sock2.o \
	openssl/crypto/bio/bf_buff.o \
	openssl/crypto/bio/bf_lbuf.o \
	openssl/crypto/bio/bf_nbio.o \
	openssl/crypto/bio/bf_null.o \
	openssl/crypto/bio/bio_cb.o \
	openssl/crypto/bio/bio_err.o \
	openssl/crypto/bio/bio_lib.o \
	openssl/crypto/bio/bio_meth.o \
	openssl/crypto/bio/bss_acpt.o \
	openssl/crypto/bio/bss_bio.o \
	openssl/crypto/bio/bss_conn.o \
	openssl/crypto/bio/bss_dgram.o \
	openssl/crypto/bio/bss_fd.o \
	openssl/crypto/bio/bss_file.o \
	openssl/crypto/bio/bss_log.o \
	openssl/crypto/bio/bss_mem.o \
	openssl/crypto/bio/bss_null.o \
	openssl/crypto/bio/bss_sock.o \
	openssl/crypto/blake2/blake2b.o \
	openssl/crypto/blake2/blake2s.o \
	openssl/crypto/blake2/m_blake2b.o \
	openssl/crypto/blake2/m_blake2s.o \
	openssl/crypto/bn/bn_add.o \
	openssl/crypto/bn/bn_asm.o \
	openssl/crypto/bn/bn_blind.o \
	openssl/crypto/bn/bn_const.o \
	openssl/crypto/bn/bn_ctx.o \
	openssl/crypto/bn/bn_depr.o \
	openssl/crypto/bn/bn_dh.o \
	openssl/crypto/bn/bn_div.o \
	openssl/crypto/bn/bn_err.o \
	openssl/crypto/bn/bn_exp.o \
	openssl/crypto/bn/bn_exp2.o \
	openssl/crypto/bn/bn_gcd.o \
	openssl/crypto/bn/bn_gf2m.o \
	openssl/crypto/bn/bn_intern.o \
	openssl/crypto/bn/bn_kron.o \
	openssl/crypto/bn/bn_lib.o \
	openssl/crypto/bn/bn_mod.o \
	openssl/crypto/bn/bn_mont.o \
	openssl/crypto/bn/bn_mpi.o \
	openssl/crypto/bn/bn_mul.o \
	openssl/crypto/bn/bn_nist.o \
	openssl/crypto/bn/bn_prime.o \
	openssl/crypto/bn/bn_print.o \
	openssl/crypto/bn/bn_rand.o \
	openssl/crypto/bn/bn_recp.o \
	openssl/crypto/bn/bn_shift.o \
	openssl/crypto/bn/bn_sqr.o \
	openssl/crypto/bn/bn_sqrt.o \
	openssl/crypto/bn/bn_srp.o \
	openssl/crypto/bn/bn_word.o \
	openssl/crypto/bn/bn_x931p.o \
	openssl/crypto/bn/rsaz_exp.o \
	openssl/crypto/buffer/buf_err.o \
	openssl/crypto/buffer/buffer.o \
	openssl/crypto/chacha/chacha_enc.o \
	openssl/crypto/cmac/cm_ameth.o \
	openssl/crypto/cmac/cm_pmeth.o \
	openssl/crypto/cmac/cmac.o \
	openssl/crypto/conf/conf_api.o \
	openssl/crypto/conf/conf_def.o \
	openssl/crypto/conf/conf_err.o \
	openssl/crypto/conf/conf_lib.o \
	openssl/crypto/conf/conf_mall.o \
	openssl/crypto/conf/conf_mod.o \
	openssl/crypto/conf/conf_sap.o \
	openssl/crypto/cpt_err.o \
	openssl/crypto/cryptlib.o \
	openssl/crypto/ct/ct_b64.o \
	openssl/crypto/ct/ct_err.o \
	openssl/crypto/ct/ct_log.o \
	openssl/crypto/ct/ct_oct.o \
	openssl/crypto/ct/ct_policy.o \
	openssl/crypto/ct/ct_prn.o \
	openssl/crypto/ct/ct_sct.o \
	openssl/crypto/ct/ct_sct_ctx.o \
	openssl/crypto/ct/ct_vfy.o \
	openssl/crypto/ct/ct_x509v3.o \
	openssl/crypto/cversion.o \
	openssl/crypto/dh/dh_ameth.o \
	openssl/crypto/dh/dh_asn1.o \
	openssl/crypto/dh/dh_check.o \
	openssl/crypto/dh/dh_depr.o \
	openssl/crypto/dh/dh_err.o \
	openssl/crypto/dh/dh_gen.o \
	openssl/crypto/dh/dh_kdf.o \
	openssl/crypto/dh/dh_key.o \
	openssl/crypto/dh/dh_lib.o \
	openssl/crypto/dh/dh_meth.o \
	openssl/crypto/dh/dh_pmeth.o \
	openssl/crypto/dh/dh_prn.o \
	openssl/crypto/dh/dh_rfc5114.o \
	openssl/crypto/dsa/dsa_ameth.o \
	openssl/crypto/dsa/dsa_asn1.o \
	openssl/crypto/dsa/dsa_depr.o \
	openssl/crypto/dsa/dsa_err.o \
	openssl/crypto/dsa/dsa_gen.o \
	openssl/crypto/dsa/dsa_key.o \
	openssl/crypto/dsa/dsa_lib.o \
	openssl/crypto/dsa/dsa_meth.o \
	openssl/crypto/dsa/dsa_ossl.o \
	openssl/crypto/dsa/dsa_pmeth.o \
	openssl/crypto/dsa/dsa_prn.o \
	openssl/crypto/dsa/dsa_sign.o \
	openssl/crypto/dsa/dsa_vrf.o \
	openssl/crypto/dso/dso_dl.o \
	openssl/crypto/dso/dso_dlfcn.o \
	openssl/crypto/dso/dso_err.o \
	openssl/crypto/dso/dso_lib.o \
	openssl/crypto/dso/dso_openssl.o \
	openssl/crypto/dso/dso_vms.o \
	openssl/crypto/dso/dso_win32.o \
	openssl/crypto/ebcdic.o \
	openssl/crypto/ec/curve25519.o \
	openssl/crypto/ec/ec2_mult.o \
	openssl/crypto/ec/ec2_oct.o \
	openssl/crypto/ec/ec2_smpl.o \
	openssl/crypto/ec/ec_ameth.o \
	openssl/crypto/ec/ec_asn1.o \
	openssl/crypto/ec/ec_check.o \
	openssl/crypto/ec/ec_curve.o \
	openssl/crypto/ec/ec_cvt.o \
	openssl/crypto/ec/ec_err.o \
	openssl/crypto/ec/ec_key.o \
	openssl/crypto/ec/ec_kmeth.o \
	openssl/crypto/ec/ec_lib.o \
	openssl/crypto/ec/ec_mult.o \
	openssl/crypto/ec/ec_oct.o \
	openssl/crypto/ec/ec_pmeth.o \
	openssl/crypto/ec/ec_print.o \
	openssl/crypto/ec/ecdh_kdf.o \
	openssl/crypto/ec/ecdh_ossl.o \
	openssl/crypto/ec/ecdsa_ossl.o \
	openssl/crypto/ec/ecdsa_sign.o \
	openssl/crypto/ec/ecdsa_vrf.o \
	openssl/crypto/ec/eck_prn.o \
	openssl/crypto/ec/ecp_mont.o \
	openssl/crypto/ec/ecp_nist.o \
	openssl/crypto/ec/ecp_nistp224.o \
	openssl/crypto/ec/ecp_nistp256.o \
	openssl/crypto/ec/ecp_nistp521.o \
	openssl/crypto/ec/ecp_nistputil.o \
	openssl/crypto/ec/ecx_meth.o \
	openssl/crypto/ec/ecp_oct.o \
	openssl/crypto/ec/ecp_smpl.o \
	openssl/crypto/engine/eng_all.o \
	openssl/crypto/engine/eng_cnf.o \
	openssl/crypto/engine/eng_cryptodev.o \
	openssl/crypto/engine/eng_ctrl.o \
	openssl/crypto/engine/eng_dyn.o \
	openssl/crypto/engine/eng_err.o \
	openssl/crypto/engine/eng_fat.o \
	openssl/crypto/engine/eng_init.o \
	openssl/crypto/engine/eng_lib.o \
	openssl/crypto/engine/eng_list.o \
	openssl/crypto/engine/eng_openssl.o \
	openssl/crypto/engine/eng_pkey.o \
	openssl/crypto/engine/eng_rdrand.o \
	openssl/crypto/engine/eng_table.o \
	openssl/crypto/engine/tb_asnmth.o \
	openssl/crypto/engine/tb_cipher.o \
	openssl/crypto/engine/tb_dh.o \
	openssl/crypto/engine/tb_digest.o \
	openssl/crypto/engine/tb_dsa.o \
	openssl/crypto/engine/tb_eckey.o \
	openssl/crypto/engine/tb_pkmeth.o \
	openssl/crypto/engine/tb_rand.o \
	openssl/crypto/engine/tb_rsa.o \
	openssl/crypto/err/err.o \
	openssl/crypto/err/err_all.o \
	openssl/crypto/err/err_prn.o \
	openssl/crypto/evp/bio_b64.o \
	openssl/crypto/evp/bio_enc.o \
	openssl/crypto/evp/bio_md.o \
	openssl/crypto/evp/bio_ok.o \
	openssl/crypto/evp/c_allc.o \
	openssl/crypto/evp/c_alld.o \
	openssl/crypto/evp/cmeth_lib.o \
	openssl/crypto/evp/digest.o \
	openssl/crypto/evp/e_aes.o \
	openssl/crypto/evp/e_aes_cbc_hmac_sha1.o \
	openssl/crypto/evp/e_aes_cbc_hmac_sha256.o \
	openssl/crypto/evp/e_cast.o \
	openssl/crypto/evp/e_chacha20_poly1305.o \
	openssl/crypto/evp/e_des.o \
	openssl/crypto/evp/e_des3.o \
	openssl/crypto/evp/e_idea.o \
	openssl/crypto/evp/e_null.o \
	openssl/crypto/evp/e_old.o \
	openssl/crypto/evp/e_rc2.o \
	openssl/crypto/evp/e_rc4.o \
	openssl/crypto/evp/e_rc4_hmac_md5.o \
	openssl/crypto/evp/e_rc5.o \
	openssl/crypto/evp/e_seed.o \
	openssl/crypto/evp/e_xcbc_d.o \
	openssl/crypto/evp/encode.o \
	openssl/crypto/evp/evp_cnf.o \
	openssl/crypto/evp/evp_enc.o \
	openssl/crypto/evp/evp_err.o \
	openssl/crypto/evp/evp_key.o \
	openssl/crypto/evp/evp_lib.o \
	openssl/crypto/evp/evp_pbe.o \
	openssl/crypto/evp/evp_pkey.o \
	openssl/crypto/evp/m_md2.o \
	openssl/crypto/evp/m_md4.o \
	openssl/crypto/evp/m_md5.o \
	openssl/crypto/evp/m_md5_sha1.o \
	openssl/crypto/evp/m_mdc2.o \
	openssl/crypto/evp/m_null.o \
	openssl/crypto/evp/m_ripemd.o \
	openssl/crypto/evp/m_sha1.o \
	openssl/crypto/evp/m_sigver.o \
	openssl/crypto/evp/m_wp.o \
	openssl/crypto/evp/names.o \
	openssl/crypto/evp/p5_crpt.o \
	openssl/crypto/evp/p5_crpt2.o \
	openssl/crypto/evp/p_dec.o \
	openssl/crypto/evp/p_enc.o \
	openssl/crypto/evp/p_lib.o \
	openssl/crypto/evp/p_open.o \
	openssl/crypto/evp/p_seal.o \
	openssl/crypto/evp/p_sign.o \
	openssl/crypto/evp/p_verify.o \
	openssl/crypto/evp/pmeth_fn.o \
	openssl/crypto/evp/pmeth_gn.o \
	openssl/crypto/evp/pmeth_lib.o \
	openssl/crypto/evp/scrypt.o \
	openssl/crypto/ex_data.o \
	openssl/crypto/hmac/hm_ameth.o \
	openssl/crypto/hmac/hm_pmeth.o \
	openssl/crypto/hmac/hmac.o \
	openssl/crypto/init.o \
	openssl/crypto/kdf/hkdf.o \
	openssl/crypto/kdf/kdf_err.o \
	openssl/crypto/kdf/tls1_prf.o \
	openssl/crypto/lhash/lh_stats.o \
	openssl/crypto/lhash/lhash.o \
	openssl/crypto/md5/md5_dgst.o \
	openssl/crypto/md5/md5_one.o \
	openssl/crypto/mem.o \
	openssl/crypto/mem_clr.o \
	openssl/crypto/mem_dbg.o \
	openssl/crypto/mem_sec.o \
	openssl/crypto/modes/cbc128.o \
	openssl/crypto/modes/ccm128.o \
	openssl/crypto/modes/cfb128.o \
	openssl/crypto/modes/ctr128.o \
	openssl/crypto/modes/cts128.o \
	openssl/crypto/modes/gcm128.o \
	openssl/crypto/modes/ocb128.o \
	openssl/crypto/modes/ofb128.o \
	openssl/crypto/modes/wrap128.o \
	openssl/crypto/modes/xts128.o \
	openssl/crypto/o_dir.o \
	openssl/crypto/o_fips.o \
	openssl/crypto/o_fopen.o \
	openssl/crypto/o_init.o \
	openssl/crypto/o_str.o \
	openssl/crypto/o_time.o \
	openssl/crypto/objects/o_names.o \
	openssl/crypto/objects/obj_dat.o \
	openssl/crypto/objects/obj_err.o \
	openssl/crypto/objects/obj_lib.o \
	openssl/crypto/objects/obj_xref.o \
	openssl/crypto/ocsp/ocsp_asn.o \
	openssl/crypto/ocsp/ocsp_cl.o \
	openssl/crypto/ocsp/ocsp_err.o \
	openssl/crypto/ocsp/ocsp_ext.o \
	openssl/crypto/ocsp/ocsp_ht.o \
	openssl/crypto/ocsp/ocsp_lib.o \
	openssl/crypto/ocsp/ocsp_prn.o \
	openssl/crypto/ocsp/ocsp_srv.o \
	openssl/crypto/ocsp/ocsp_vfy.o \
	openssl/crypto/ocsp/v3_ocsp.o \
	openssl/crypto/pem/pem_all.o \
	openssl/crypto/pem/pem_err.o \
	openssl/crypto/pem/pem_info.o \
	openssl/crypto/pem/pem_lib.o \
	openssl/crypto/pem/pem_oth.o \
	openssl/crypto/pem/pem_pk8.o \
	openssl/crypto/pem/pem_pkey.o \
	openssl/crypto/pem/pem_sign.o \
	openssl/crypto/pem/pem_x509.o \
	openssl/crypto/pem/pem_xaux.o \
	openssl/crypto/pem/pvkfmt.o \
	openssl/crypto/pkcs12/p12_add.o \
	openssl/crypto/pkcs12/p12_asn.o \
	openssl/crypto/pkcs12/p12_attr.o \
	openssl/crypto/pkcs12/p12_crpt.o \
	openssl/crypto/pkcs12/p12_crt.o \
	openssl/crypto/pkcs12/p12_decr.o \
	openssl/crypto/pkcs12/p12_init.o \
	openssl/crypto/pkcs12/p12_key.o \
	openssl/crypto/pkcs12/p12_kiss.o \
	openssl/crypto/pkcs12/p12_mutl.o \
	openssl/crypto/pkcs12/p12_npas.o \
	openssl/crypto/pkcs12/p12_p8d.o \
	openssl/crypto/pkcs12/p12_p8e.o \
	openssl/crypto/pkcs12/p12_sbag.o \
	openssl/crypto/pkcs12/p12_utl.o \
	openssl/crypto/pkcs12/pk12err.o \
	openssl/crypto/pkcs7/bio_pk7.o \
	openssl/crypto/pkcs7/pk7_asn1.o \
	openssl/crypto/pkcs7/pk7_attr.o \
	openssl/crypto/pkcs7/pk7_dgst.o \
	openssl/crypto/pkcs7/pk7_doit.o \
	openssl/crypto/pkcs7/pk7_lib.o \
	openssl/crypto/pkcs7/pk7_mime.o \
	openssl/crypto/pkcs7/pk7_smime.o \
	openssl/crypto/pkcs7/pkcs7err.o \
	openssl/crypto/poly1305/poly1305.o \
	openssl/crypto/rand/md_rand.o \
	openssl/crypto/rand/rand_egd.o \
	openssl/crypto/rand/rand_err.o \
	openssl/crypto/rand/rand_lib.o \
	openssl/crypto/rand/rand_unix.o \
	openssl/crypto/rand/rand_vms.o \
	openssl/crypto/rand/rand_win.o \
	openssl/crypto/rand/randfile.o \
	openssl/crypto/rsa/rsa_ameth.o \
	openssl/crypto/rsa/rsa_asn1.o \
	openssl/crypto/rsa/rsa_chk.o \
	openssl/crypto/rsa/rsa_crpt.o \
	openssl/crypto/rsa/rsa_depr.o \
	openssl/crypto/rsa/rsa_err.o \
	openssl/crypto/rsa/rsa_gen.o \
	openssl/crypto/rsa/rsa_lib.o \
	openssl/crypto/rsa/rsa_meth.o \
	openssl/crypto/rsa/rsa_none.o \
	openssl/crypto/rsa/rsa_null.o \
	openssl/crypto/rsa/rsa_oaep.o \
	openssl/crypto/rsa/rsa_ossl.o \
	openssl/crypto/rsa/rsa_pk1.o \
	openssl/crypto/rsa/rsa_pmeth.o \
	openssl/crypto/rsa/rsa_prn.o \
	openssl/crypto/rsa/rsa_pss.o \
	openssl/crypto/rsa/rsa_saos.o \
	openssl/crypto/rsa/rsa_sign.o \
	openssl/crypto/rsa/rsa_ssl.o \
	openssl/crypto/rsa/rsa_x931.o \
	openssl/crypto/rsa/rsa_x931g.o \
	openssl/crypto/seed/seed.o \
	openssl/crypto/seed/seed_cbc.o \
	openssl/crypto/seed/seed_cfb.o \
	openssl/crypto/seed/seed_ecb.o \
	openssl/crypto/seed/seed_ofb.o \
	openssl/crypto/sha/sha1_one.o \
	openssl/crypto/sha/sha1dgst.o \
	openssl/crypto/sha/sha256.o \
	openssl/crypto/sha/sha512.o \
	openssl/crypto/stack/stack.o \
	openssl/crypto/threads_none.o \
	openssl/crypto/threads_pthread.o \
	openssl/crypto/threads_win.o \
	openssl/crypto/ts/ts_asn1.o \
	openssl/crypto/ts/ts_conf.o \
	openssl/crypto/ts/ts_err.o \
	openssl/crypto/ts/ts_lib.o \
	openssl/crypto/ts/ts_req_print.o \
	openssl/crypto/ts/ts_req_utils.o \
	openssl/crypto/ts/ts_rsp_print.o \
	openssl/crypto/ts/ts_rsp_sign.o \
	openssl/crypto/ts/ts_rsp_utils.o \
	openssl/crypto/ts/ts_rsp_verify.o \
	openssl/crypto/ts/ts_verify_ctx.o \
	openssl/crypto/txt_db/txt_db.o \
	openssl/crypto/ui/ui_err.o \
	openssl/crypto/ui/ui_lib.o \
	openssl/crypto/ui/ui_openssl.o \
	openssl/crypto/ui/ui_util.o \
	openssl/crypto/uid.o \
	openssl/crypto/x509/by_dir.o \
	openssl/crypto/x509/by_file.o \
	openssl/crypto/x509/t_crl.o \
	openssl/crypto/x509/t_req.o \
	openssl/crypto/x509/t_x509.o \
	openssl/crypto/x509/x509_att.o \
	openssl/crypto/x509/x509_cmp.o \
	openssl/crypto/x509/x509_d2.o \
	openssl/crypto/x509/x509_def.o \
	openssl/crypto/x509/x509_err.o \
	openssl/crypto/x509/x509_ext.o \
	openssl/crypto/x509/x509_lu.o \
	openssl/crypto/x509/x509_obj.o \
	openssl/crypto/x509/x509_r2x.o \
	openssl/crypto/x509/x509_req.o \
	openssl/crypto/x509/x509_set.o \
	openssl/crypto/x509/x509_trs.o \
	openssl/crypto/x509/x509_txt.o \
	openssl/crypto/x509/x509_v3.o \
	openssl/crypto/x509/x509_vfy.o \
	openssl/crypto/x509/x509_vpm.o \
	openssl/crypto/x509/x509cset.o \
	openssl/crypto/x509/x509name.o \
	openssl/crypto/x509/x509rset.o \
	openssl/crypto/x509/x509spki.o \
	openssl/crypto/x509/x509type.o \
	openssl/crypto/x509/x_all.o \
	openssl/crypto/x509/x_attrib.o \
	openssl/crypto/x509/x_crl.o \
	openssl/crypto/x509/x_exten.o \
	openssl/crypto/x509/x_name.o \
	openssl/crypto/x509/x_pubkey.o \
	openssl/crypto/x509/x_req.o \
	openssl/crypto/x509/x_x509.o \
	openssl/crypto/x509/x_x509a.o \
	openssl/crypto/x509v3/pcy_cache.o \
	openssl/crypto/x509v3/pcy_data.o \
	openssl/crypto/x509v3/pcy_lib.o \
	openssl/crypto/x509v3/pcy_map.o \
	openssl/crypto/x509v3/pcy_node.o \
	openssl/crypto/x509v3/pcy_tree.o \
	openssl/crypto/x509v3/v3_addr.o \
	openssl/crypto/x509v3/v3_akey.o \
	openssl/crypto/x509v3/v3_akeya.o \
	openssl/crypto/x509v3/v3_alt.o \
	openssl/crypto/x509v3/v3_asid.o \
	openssl/crypto/x509v3/v3_bcons.o \
	openssl/crypto/x509v3/v3_bitst.o \
	openssl/crypto/x509v3/v3_conf.o \
	openssl/crypto/x509v3/v3_cpols.o \
	openssl/crypto/x509v3/v3_crld.o \
	openssl/crypto/x509v3/v3_enum.o \
	openssl/crypto/x509v3/v3_extku.o \
	openssl/crypto/x509v3/v3_genn.o \
	openssl/crypto/x509v3/v3_ia5.o \
	openssl/crypto/x509v3/v3_info.o \
	openssl/crypto/x509v3/v3_int.o \
	openssl/crypto/x509v3/v3_lib.o \
	openssl/crypto/x509v3/v3_ncons.o \
	openssl/crypto/x509v3/v3_pci.o \
	openssl/crypto/x509v3/v3_pcia.o \
	openssl/crypto/x509v3/v3_pcons.o \
	openssl/crypto/x509v3/v3_pku.o \
	openssl/crypto/x509v3/v3_pmaps.o \
	openssl/crypto/x509v3/v3_prn.o \
	openssl/crypto/x509v3/v3_purp.o \
	openssl/crypto/x509v3/v3_skey.o \
	openssl/crypto/x509v3/v3_sxnet.o \
	openssl/crypto/x509v3/v3_tlsf.o \
	openssl/crypto/x509v3/v3_utl.o \
	openssl/crypto/x509v3/v3err.o

ifeq ($(TARGET_OS),android)
	ifeq ($(TARGET_CPU),arm)
		_OBJECTS = $(filter-out \
			openssl/crypto/aes/aes_core.o \
			openssl/crypto/mem_clr.o \
			, $(OPENSSL_OBJECTS))
		_OBJECTS += openssl/crypto/aes/asm/aes-armv4-android-arm.o \
			openssl/crypto/aes/asm/aesv8-armx-android-arm.o \
			openssl/crypto/aes/asm/bsaes-armv7-android-arm.o \
			openssl/crypto/armcap.o \
			openssl/crypto/armv4cpuid-android-arm.o \
			openssl/crypto/bn/asm/armv4-gf2m-android-arm.o \
			openssl/crypto/bn/asm/armv4-mont-android-arm.o \
			openssl/crypto/modes/asm/ghash-armv4-android-arm.o \
			openssl/crypto/modes/asm/ghashv8-armx-android-arm.o \
			openssl/crypto/sha/asm/sha1-armv4-large-android-arm.o \
			openssl/crypto/sha/asm/sha256-armv4-android-arm.o \
			openssl/crypto/sha/asm/sha512-armv4-android-arm.o
		DEFINES += -DOPENSSL_BN_ASM_GF2m \
			-DOPENSSL_BN_ASM_MONT \
			-DAES_ASM \
			-DGHASH_ASM \
			-DSHA1_ASM \
			-DSHA256_ASM \
			-DSHA512_ASM \
			-DOPENSSL_CPUID_OBJ
	else ifeq ($(TARGET_CPU),arm64)
		_OBJECTS = $(filter-out \
			openssl/crypto/mem_clr.o \
			, $(OPENSSL_OBJECTS))
		_OBJECTS += openssl/crypto/aes/asm/aesv8-armx-android-arm64.o \
			openssl/crypto/aes/asm/vpaes-armv8-android-arm64.o \
			openssl/crypto/arm64cpuid-android-arm64.o \
			openssl/crypto/armcap.o \
			openssl/crypto/bn/asm/armv8-mont-android-arm64.o \
			openssl/crypto/modes/asm/ghashv8-armx-android-arm64.o \
			openssl/crypto/sha/asm/sha1-armv8-android-arm64.o \
			openssl/crypto/sha/asm/sha256-armv8-android-arm64.o \
			openssl/crypto/sha/asm/sha512-armv8-android-arm64.o
		DEFINES += -DOPENSSL_BN_ASM_MONT \
			-DVPAES_ASM \
			-DSHA1_ASM \
			-DSHA256_ASM \
			-DSHA512_ASM \
			-DOPENSSL_CPUID_OBJ
	else
		_OBJECTS = $(OPENSSL_OBJECTS)
	endif
else ifeq ($(TARGET_OS),ios)
	ifeq ($(TARGET_CPU),arm)
		_OBJECTS = $(filter-out \
			openssl/crypto/aes/aes_core.o \
			openssl/crypto/mem_clr.o \
			, $(OPENSSL_OBJECTS))
		_OBJECTS += openssl/crypto/aes/asm/aes-armv4-ios-arm.o \
			openssl/crypto/aes/asm/aesv8-armx-ios-arm.o \
			openssl/crypto/aes/asm/bsaes-armv7-ios-arm.o \
			openssl/crypto/armcap.o \
			openssl/crypto/armv4cpuid-ios-arm.o \
			openssl/crypto/bn/asm/armv4-gf2m-ios-arm.o \
			openssl/crypto/bn/asm/armv4-mont-ios-arm.o \
			openssl/crypto/modes/asm/ghash-armv4-ios-arm.o \
			openssl/crypto/modes/asm/ghashv8-armx-ios-arm.o \
			openssl/crypto/sha/asm/sha1-armv4-large-ios-arm.o \
			openssl/crypto/sha/asm/sha256-armv4-ios-arm.o \
			openssl/crypto/sha/asm/sha512-armv4-ios-arm.o
		DEFINES += -DOPENSSL_BN_ASM_GF2m \
			-DOPENSSL_BN_ASM_MONT \
			-DAES_ASM \
			-DGHASH_ASM \
			-DSHA1_ASM \
			-DSHA256_ASM \
			-DSHA512_ASM \
			-DOPENSSL_CPUID_OBJ
	else ifeq ($(TARGET_CPU),arm64)
		_OBJECTS = $(filter-out \
			openssl/crypto/mem_clr.o \
			, $(OPENSSL_OBJECTS))
		_OBJECTS += openssl/crypto/aes/asm/aesv8-armx-ios-arm64.o \
			openssl/crypto/aes/asm/vpaes-armv8-ios-arm64.o \
			openssl/crypto/arm64cpuid-ios-arm64.o \
			openssl/crypto/armcap.o \
			openssl/crypto/bn/asm/armv8-mont-ios-arm64.o \
			openssl/crypto/modes/asm/ghashv8-armx-ios-arm64.o \
			openssl/crypto/sha/asm/sha1-armv8-ios-arm64.o \
			openssl/crypto/sha/asm/sha256-armv8-ios-arm64.o \
			openssl/crypto/sha/asm/sha512-armv8-ios-arm64.o
		DEFINES += -DOPENSSL_BN_ASM_MONT \
			-DVPAES_ASM \
			-DSHA1_ASM \
			-DSHA256_ASM \
			-DSHA512_ASM \
			-DOPENSSL_CPUID_OBJ
	else
		_OBJECTS = $(OPENSSL_OBJECTS)
	endif
endif

_OBJECTS += BigNum.o \
	Cipher.o \
	Hex.o \
	Key.o \
	MessageDigest.o \
	OpenSSLException.o \
	Srp6.o \
	ZeroKitClientNative.o

OBJECTS = $(patsubst %,$(OUTDIR)/%,$(_OBJECTS))

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJECTS) openssl/opensslconf.h *.o *.so.debug openssl/crypto/sha/asm/*.[sS] test

ifeq ($(TARGET_OS),android)
$(TARGET): $(OBJECTS)
	$(LD) $^ -o $@.debug $(LDFLAGS) -shared -Wl,-soname,$@ -Wl,--version-script,libZeroKitClientNative.ver
	$(OBJCOPY) -S -g -x -X --strip-unneeded --add-gnu-debuglink=$@.debug $@.debug $@
else ifeq ($(TARGET_OS),ios)
$(TARGET): $(OBJECTS)
	rm -rf $@
	$(LIBTOOL) -static -o $@ $^
endif

openssl/opensslconf.h: opensslconf.h
	cp -v opensslconf.h openssl/opensslconf.h

$(OUTDIR)/%.o: %.c $(HEADERS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR)/openssl/crypto/asn1/x_int64.o: openssl/crypto/asn1/x_int64.c $(HEADERS)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -Wno-format -c $< -o $@

$(OUTDIR)/%.o: %.cpp $(HEADERS)
	mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

ifeq ($(TARGET_OS),android)
$(OUTDIR)/%.o: %.S $(HEADERS)
	mkdir -p $(@D)
	$(AS) $(ASFLAGS) -c $< -o $@

ifeq ($(TARGET_CPU),arm)
%-android-arm.S: %.pl
	perl $< void > $@
else ifeq ($(TARGET_CPU),arm64)
%-android-arm64.S: %.pl
	perl $< linux64 > $@

openssl/crypto/sha/asm/sha512-armv8-android-arm64.S: openssl/crypto/sha/asm/sha512-armv8.pl
	perl $< linux64 $@

openssl/crypto/sha/asm/sha256-armv8-android-arm64.S: openssl/crypto/sha/asm/sha512-armv8.pl
	perl $< linux64 $@
endif
else ifeq ($(TARGET_OS),ios)
$(OUTDIR)/%.o: %.s $(HEADERS)
	mkdir -p $(@D)
	$(AS) $(ASFLAGS) -c $< -o $@

ifeq ($(TARGET_CPU),arm)
%-ios-arm.s: %.pl
	perl $< ios32 > $@
else ifeq ($(TARGET_CPU),arm64)
%-ios-arm64.s: %.pl
	perl $< ios64 > $@

openssl/crypto/sha/asm/sha512-armv8-ios-arm64.s: openssl/crypto/sha/asm/sha512-armv8.pl
	perl $< ios64 $@

openssl/crypto/sha/asm/sha256-armv8-ios-arm64.s: openssl/crypto/sha/asm/sha512-armv8.pl
	perl $< ios64 $@
endif
endif

