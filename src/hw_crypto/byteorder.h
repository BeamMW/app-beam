// Copyright 2018 The Beam Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

// This nasty macro is under MIT license (afaik)
#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#  if (defined(__BYTE_ORDER__)  && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
     (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
     (defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN) || \
     (defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN) || \
     (defined(__sun) && defined(__SVR4) && defined(_BIG_ENDIAN)) || \
     defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
     defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__) || \
     defined(_M_PPC)
#        define __BIG_ENDIAN__
#  elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || /* gcc */\
     (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) /* linux header */ || \
     (defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN) || \
     (defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN) /* mingw header */ ||  \
     (defined(__sun) && defined(__SVR4) && defined(_LITTLE_ENDIAN)) || /* solaris */ \
     defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) || \
     defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__) || \
     defined(_M_IX86) || defined(_M_X64) || defined(_M_IA64) || /* msvc for intel processors */ \
     defined(_M_ARM) /* msvc code on arm executes in little endian mode */
#        define __LITTLE_ENDIAN__
#  elif
#    error can not detect endian-ness
#  endif
#endif

#ifdef _MSC_VER

	inline uint16_t bswap16(uint16_t x) { return _byteswap_ushort(x); }
	inline uint32_t bswap32(uint32_t x) { static_assert(sizeof(uint32_t) == sizeof(unsigned long), ""); return _byteswap_ulong(x); }
	inline uint64_t bswap64(uint64_t x) { return _byteswap_uint64(x); }

#else // _MSC_VER

	inline uint16_t bswap16(uint16_t x) { return __builtin_bswap16(x); }
	inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }
	inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }

#endif // _MSC_VER

#ifdef __LITTLE_ENDIAN__

	inline uint16_t bswap16_be(uint16_t x) { return bswap16(x); }
	inline uint32_t bswap32_be(uint32_t x) { return bswap32(x); }
	inline uint64_t bswap64_be(uint64_t x) { return bswap64(x); }

	inline uint16_t bswap16_le(uint16_t x) { return x; }
	inline uint32_t bswap32_le(uint32_t x) { return x; }
	inline uint64_t bswap64_le(uint64_t x) { return x; }

#else // __LITTLE_ENDIAN__

	inline uint16_t bswap16_le(uint16_t x) { return bswap16(x); }
	inline uint32_t bswap32_le(uint32_t x) { return bswap32(x); }
	inline uint64_t bswap64_le(uint64_t x) { return bswap64(x); }

	inline uint16_t bswap16_be(uint16_t x) { return x; }
	inline uint32_t bswap32_be(uint32_t x) { return x; }
	inline uint64_t bswap64_be(uint64_t x) { return x; }

#endif // __LITTLE_ENDIAN__
