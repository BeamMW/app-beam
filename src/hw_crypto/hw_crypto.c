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

#include <assert.h>
#include "multimac.h"
#include "oracle.h"
#include "noncegen.h"
#include "coinid.h"
#include "kdf.h"
#include "rangeproof.h"
#include "sign.h"
#include "keykeeper.h"
#include "byteorder.h"

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wunused-function"
#else
#	pragma warning (push, 0) // suppress warnings from secp256k1
#	pragma warning (disable: 4706 4701) // assignment within conditional expression
#	define __attribute__(x) __declspec x
#endif

#ifndef UNUSED
#	define UNUSED(x) (x)
#endif // UNUSED

#if BeamCrypto_ScarceStack
#	define __stack_hungry__ __attribute__((noinline))
#else // BeamCrypto_ScarceStack
#	define __stack_hungry__
#endif // BeamCrypto_ScarceStack


#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/hash_impl.h"

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
#	pragma GCC diagnostic pop
#else
#	pragma warning (default: 4706 4701)
#	pragma warning (pop)
#endif

#define SECURE_ERASE_OBJ(x) SecureEraseMem(&(x), sizeof(x))
#define ZERO_OBJ(x) memset(&(x), 0, sizeof(x))

#ifdef USE_SCALAR_4X64
typedef uint64_t secp256k1_scalar_uint;
#else // USE_SCALAR_4X64
typedef uint32_t secp256k1_scalar_uint;
#endif // USE_SCALAR_4X64

#ifndef _countof
#	define _countof(arr) sizeof(arr) / sizeof((arr)[0])
#endif

#define secp256k1_scalar_WordBits (sizeof(secp256k1_scalar_uint) * 8)



//////////////////////////////
// MultiMac
typedef struct
{
	int m_Word;
	secp256k1_scalar_uint m_Msk;
} BitWalker;

inline static void BitWalker_SetPos(BitWalker* p, uint8_t iBit)
{
	p->m_Word = iBit / secp256k1_scalar_WordBits;
	p->m_Msk = ((secp256k1_scalar_uint) 1) << (iBit & (secp256k1_scalar_WordBits - 1));
}

inline static void BitWalker_MoveUp(BitWalker* p)
{
	if (!(p->m_Msk <<= 1))
	{
		p->m_Msk = 1;
		p->m_Word++;
	}
}

inline static void BitWalker_MoveDown(BitWalker* p)
{
	if (!(p->m_Msk >>= 1))
	{
		p->m_Msk = ((secp256k1_scalar_uint) 1) << (secp256k1_scalar_WordBits - 1);

		p->m_Word--;
	}
}

inline static secp256k1_scalar_uint BitWalker_get(const BitWalker* p, const secp256k1_scalar* pK)
{
	return pK->d[p->m_Word] & p->m_Msk;
}

inline static secp256k1_scalar_uint BitWalker_xor(const BitWalker* p, secp256k1_scalar* pK)
{
	return (pK->d[p->m_Word] ^= p->m_Msk) & p->m_Msk;
}

#define c_WNaf_Invalid 0x80
static_assert((c_MultiMac_OddCount(c_MultiMac_nBits_Rangeproof) * 2) < c_WNaf_Invalid, "");
static_assert((c_MultiMac_OddCount(c_MultiMac_nBits_H) * 2) < c_WNaf_Invalid, "");
static_assert((c_MultiMac_OddCount(c_MultiMac_nBits_Custom) * 2) < c_WNaf_Invalid, "");

inline static void WNaf_Cursor_SetInvalid(MultiMac_WNaf* p)
{
	p->m_iBit = 0xff;
	p->m_iElement = c_WNaf_Invalid;
}


static int WNaf_Cursor_Init(MultiMac_WNaf* p, secp256k1_scalar* pK, unsigned int nMaxWnd)
{
	// Choose the optimal strategy
	// Pass from lower bits up, look for 1.
	WNaf_Cursor_SetInvalid(p);

	int carry = 0;
	unsigned int nWndLen = 0;
	BitWalker bw, bw0;
	bw.m_Word = 0;
	bw.m_Msk = 1;

	for (unsigned int iBit = 0; iBit < c_ECC_nBits; BitWalker_MoveUp(&bw), iBit++)
	{
		if (carry)
		{
			assert(!nWndLen);

			if (!BitWalker_xor(&bw, pK))
				continue;

			carry = 0;
		}
		else
		{
			secp256k1_scalar_uint val = BitWalker_get(&bw, pK);

			if (nWndLen)
			{
				assert(nWndLen <= nMaxWnd);

				if (val)
					p->m_iElement |= (1 << (nWndLen - 1));

				if (++nWndLen > nMaxWnd)
				{
					// word end. Make sure there's a bit set at this position. Use the bit at word beginning as a negation indicator.
					if (val)
					{
						carry = 1;
						BitWalker_xor(&bw0, pK);
					}
					else
						BitWalker_xor(&bw, pK);

					nWndLen = 0;
				}

				continue;
			}

			if (!val)
				continue;
		}

		// new window
		nWndLen = 1;
		p->m_iBit = iBit;
		p->m_iElement = 0;

		bw0 = bw;
	}

	return carry;
}

static void WNaf_Cursor_MoveNext(MultiMac_WNaf* p, const secp256k1_scalar* pK, unsigned int nMaxWnd)
{
	if (p->m_iBit <= nMaxWnd)
		return;

	BitWalker bw;
	BitWalker_SetPos(&bw, --p->m_iBit);

	// find next nnz bit
	for (; ; BitWalker_MoveDown(&bw), --p->m_iBit)
	{
		if (BitWalker_get(&bw, pK))
			break;

		if (p->m_iBit <= nMaxWnd)
		{
			WNaf_Cursor_SetInvalid(p);
			return;
		}
	}

	p->m_iBit -= nMaxWnd;
	p->m_iElement = 0;

	for (unsigned int i = 0; i < (nMaxWnd - 1); i++)
	{
		p->m_iElement <<= 1;

		BitWalker_MoveDown(&bw);
		if (BitWalker_get(&bw, pK))
			p->m_iElement |= 1;
	}

	unsigned int nMaxElements = c_MultiMac_OddCount(nMaxWnd);

	assert(p->m_iElement < nMaxElements);

	// last indicator bit
	BitWalker_MoveDown(&bw);
	if (!BitWalker_get(&bw, pK))
		// must negate instead of addition
		p->m_iElement += nMaxElements;
}

void mem_cmov(unsigned int* pDst, const unsigned int* pSrc, int flag, unsigned int nWords)
{
	const unsigned int mask0 = flag + ~((unsigned int) 0);
	const unsigned int mask1 = ~mask0;

	for (unsigned int n = 0; n < nWords; n++)
		pDst[n] = (pDst[n] & mask0) | (pSrc[n] & mask1);
}

static void MultiMac_Calculate_LoadFast(const MultiMac_Context* p, secp256k1_ge* pGe, unsigned int iGen, unsigned int iElem)
{
	unsigned int nPitch = c_MultiMac_OddCount(p->m_Fast.m_WndBits);
	assert(iElem < nPitch);

	unsigned int n = nPitch * iGen + iElem;
	secp256k1_ge_from_storage(pGe, p->m_Fast.m_pGen0 + n);
}

__stack_hungry__
static void wrap_gej_add_ge_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b /*, secp256k1_fe* rzr */)
{
	secp256k1_gej_add_ge_var(r, a, b, 0 /* rzr */);
}

__stack_hungry__
static void wrap_gej_add_zinv_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_ge* b, const secp256k1_fe* bzinv)
{
	secp256k1_gej_add_zinv_var(r, a, b, bzinv);
}

__stack_hungry__
static void wrap_gej_add_var(secp256k1_gej* r, const secp256k1_gej* a, const secp256k1_gej* b /*, secp256k1_fe* rzr */)
{
	secp256k1_gej_add_var(r, a, b, 0 /* rzr */);
}

__stack_hungry__
static int wrap_scalar_add(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b)
{
	return secp256k1_scalar_add(r, a, b);
}

__stack_hungry__
static void wrap_ge_neg(secp256k1_ge* r, const secp256k1_ge* a)
{
	secp256k1_ge_neg(r, a);
}

__stack_hungry__
static void wrap_gej_double_var(secp256k1_gej* r, const secp256k1_gej* a/*, secp256k1_fe* rzr*/)
{
	secp256k1_gej_double_var(r, a, 0 /* rzr */);
}

__stack_hungry__
static void MultiMac_Calculate_PrePhase(MultiMac_Context* const p)
{
	secp256k1_gej_set_infinity(p->m_pRes);

	if (!p->m_Fast.m_Count)
	{
		p->m_Fast.m_pZDenom = 0;
		return;
	}

	for (unsigned int i = 0; i < p->m_Fast.m_Count; i++)
	{
		MultiMac_WNaf* pWnaf = p->m_Fast.m_pWnaf + i;
		secp256k1_scalar* pS = p->m_Fast.m_pK + i;

		int carry = WNaf_Cursor_Init(pWnaf, pS, p->m_Fast.m_WndBits);
		if (carry)
		{
			secp256k1_ge ge;
			MultiMac_Calculate_LoadFast(p, &ge, i, 0);
			wrap_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge);
		}
	}
}

__stack_hungry__
static void MultiMac_Calculate_Secure_Read(secp256k1_ge* pGe, const MultiMac_Secure* pGen, unsigned int iElement)
{
	secp256k1_ge_storage ges;

	for (unsigned int j = 0; j < c_MultiMac_Secure_nCount; j++)
	{
		static_assert(sizeof(ges) == sizeof(pGen->m_pPt[j]), "");
		static_assert(!(sizeof(ges) % sizeof(unsigned int)), "");

		mem_cmov(
			(unsigned int*) &ges,
			(unsigned int*)(pGen->m_pPt + j),
			iElement == j,
			sizeof(ges) / sizeof(unsigned int));
	}

	secp256k1_ge_from_storage(pGe, &ges); // inline is ok here
	SECURE_ERASE_OBJ(ges);
}

__stack_hungry__
static void MultiMac_Calculate_SecureBit(const MultiMac_Context* p, unsigned int iBit)
{
	secp256k1_ge ge;

	static_assert(!(secp256k1_scalar_WordBits % c_MultiMac_nBits_Secure), "");

	unsigned int iWord = iBit / secp256k1_scalar_WordBits;
	unsigned int nShift = iBit % secp256k1_scalar_WordBits;
	const secp256k1_scalar_uint nMsk = ((1U << c_MultiMac_nBits_Secure) - 1);

	for (unsigned int i = 0; i < p->m_Secure.m_Count; i++)
	{
		unsigned int iElement = (p->m_Secure.m_pK[i].d[iWord] >> nShift) & nMsk;
		const MultiMac_Secure* pGen = p->m_Secure.m_pGen + i;

		MultiMac_Calculate_Secure_Read(&ge, pGen, iElement);

		if (p->m_Fast.m_pZDenom)
			wrap_gej_add_zinv_var(p->m_pRes, p->m_pRes, &ge, p->m_Fast.m_pZDenom);
		else
			wrap_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge);
	}
}

__stack_hungry__
static void MultiMac_Calculate_FastBit(const MultiMac_Context* p, unsigned int iBit)
{
	unsigned int nMaxWnd = p->m_Fast.m_WndBits;
	unsigned int nMaxElements = c_MultiMac_OddCount(nMaxWnd);

	for (unsigned int i = 0; i < p->m_Fast.m_Count; i++)
	{
		MultiMac_WNaf* pWnaf = p->m_Fast.m_pWnaf + i;

		if (((uint8_t) iBit) != pWnaf->m_iBit)
			continue;

		unsigned int iElem = pWnaf->m_iElement;

		if (c_WNaf_Invalid == iElem)
			continue;

		int bNegate = (iElem >= nMaxElements);
		if (bNegate)
		{
			iElem = (nMaxElements * 2 - 1) - iElem;
			assert(iElem < nMaxElements);
		}

		secp256k1_ge ge;
		MultiMac_Calculate_LoadFast(p, &ge, i, iElem);

		if (bNegate)
			wrap_ge_neg(&ge, &ge);

		wrap_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge);

		WNaf_Cursor_MoveNext(pWnaf, p->m_Fast.m_pK + i, nMaxWnd);
	}
}

__stack_hungry__
static void MultiMac_Calculate_PostPhase(const MultiMac_Context* p)
{
	if (p->m_Fast.m_pZDenom)
		// fix denominator
		secp256k1_fe_mul(&p->m_pRes->z, &p->m_pRes->z, p->m_Fast.m_pZDenom);

	for (unsigned int i = 0; i < p->m_Secure.m_Count; i++)
	{
		secp256k1_ge ge;
		secp256k1_ge_from_storage(&ge, p->m_Secure.m_pGen[i].m_pPt + c_MultiMac_Secure_nCount);
		wrap_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge);
	}

}

__stack_hungry__
void MultiMac_Calculate(MultiMac_Context* p)
{
	MultiMac_Calculate_PrePhase(p);

	for (unsigned int iBit = c_ECC_nBits; iBit--; )
	{
		wrap_gej_double_var(p->m_pRes, p->m_pRes); // would be fast if zero, no need to check explicitly

		if (!(iBit % c_MultiMac_nBits_Secure) && p->m_Secure.m_Count)
			MultiMac_Calculate_SecureBit(p, iBit);

		MultiMac_Calculate_FastBit(p, iBit);
	}

	MultiMac_Calculate_PostPhase(p);
}

//////////////////////////////
// Batch normalization
__stack_hungry__
static void secp256k1_gej_rescale_To_ge(secp256k1_gej* pGej, const secp256k1_fe* pZ)
{
	// equivalent of secp256k1_gej_rescale, but doesn't change z coordinate
	// A bit more effective when the value of z is known in advance (such as when normalizing)

	// object is implicitly converted into ge
	secp256k1_ge* pGe = (secp256k1_ge *) pGej;

	secp256k1_fe zz;
	secp256k1_fe_sqr(&zz, pZ);

	secp256k1_fe_mul(&pGe->x, &pGej->x, &zz);
	secp256k1_fe_mul(&pGe->y, &pGej->y, &zz);
	secp256k1_fe_mul(&pGe->y, &pGej->y, pZ);

	pGe->infinity = 0;
}

void Point_Gej_BatchRescale(secp256k1_gej*  pGej, unsigned int nCount, secp256k1_fe* pBuf, secp256k1_fe* pZDenom, int bNormalize)
{
	int iPrev = -1;
	for (unsigned int i = 0; i < nCount; i++)
	{
		if (secp256k1_gej_is_infinity(pGej + i))
		{
			((secp256k1_ge*)(pGej + i))->infinity = 1;
			continue;
		}

		if (iPrev >= 0)
			secp256k1_fe_mul(pBuf + i, pBuf + iPrev, &pGej[i].z);
		else
			pBuf[i] = pGej[i].z;

		iPrev = i;
	}

	if (iPrev < 0)
		return; // all are zero

	if (bNormalize)
		secp256k1_fe_inv(pZDenom, pBuf + iPrev); // the only expensive call
	else
		secp256k1_fe_set_int(pZDenom, 1); // can be arbitrary

	iPrev = -1;
	for (unsigned int i = nCount; i--; )
	{
		if (secp256k1_gej_is_infinity(pGej + i))
			continue;

		if (iPrev >= 0)
		{
			secp256k1_fe_mul(pBuf + iPrev, pBuf + i, pZDenom);
			secp256k1_fe_mul(pZDenom, pZDenom, &pGej[iPrev].z);

			secp256k1_gej_rescale_To_ge(pGej + iPrev, pBuf + iPrev);
		}

		iPrev = i;
	}

	assert(iPrev >= 0);

	secp256k1_gej_rescale_To_ge(pGej + iPrev, pZDenom);

	// if we're normalizing - no need to return the common denominator (it's assumed 1)
	// If we're just bringing to common denominator - we assume that 1st element is normalized by the caller, hence zDenom is already set

	/*
	if (bNormalize)
		secp256k1_gej_rescale_To_ge(pGej + iPrev, pZDenom);
	else
	{
		pBuf[iPrev] = *pZDenom;
		secp256k1_fe_mul(pZDenom, pZDenom, &pGej[iPrev].z);

		secp256k1_gej_rescale_To_ge(pGej + iPrev, pBuf + iPrev);
	}
	*/
}

__stack_hungry__
void Point_Gej_2_Normalize(secp256k1_gej* pGej)
{
	secp256k1_fe pBuf[2];
	secp256k1_fe zDenom;
	Point_Gej_BatchRescale(pGej, _countof(pBuf), pBuf, &zDenom, 1);
}

typedef struct
{
	secp256k1_ge_storage m_pPt[c_MultiMac_OddCount(c_MultiMac_nBits_Custom)]; // odd powers
	secp256k1_fe m_zDenom;
} CustomGenerator;

__stack_hungry__
void MultiMac_Fast_Custom_Init(CustomGenerator* p, const secp256k1_ge* pGe)
{
	assert(!secp256k1_ge_is_infinity(pGe));

	// calculate odd powers
	secp256k1_gej pOdds[_countof(p->m_pPt)];
	Point_Gej_from_Ge(pOdds, pGe);

	secp256k1_gej* const pX2 = (secp256k1_gej *) p->m_pPt; // reuse its mem!
	wrap_gej_double_var(pX2, pOdds);

	for (unsigned int i = 1; i < _countof(pOdds); i++)
	{
		wrap_gej_add_var(pOdds + i, pOdds + i - 1, pX2);
		assert(!secp256k1_gej_is_infinity(pOdds + i)); // odd powers of non-zero point must not be zero!
	}

	// to common denominator
	static_assert(sizeof(secp256k1_fe) * _countof(pOdds) <= sizeof(p->m_pPt), "Need this to temporary use its memory");

	Point_Gej_BatchRescale(pOdds, _countof(pOdds), (secp256k1_fe*) &p->m_pPt, &p->m_zDenom, 0);

	for (unsigned int i = 0; i < _countof(pOdds); i++)
		secp256k1_ge_to_storage(p->m_pPt + i, (secp256k1_ge*) (pOdds + i));
}

//////////////////////////////
// NonceGenerator
void NonceGenerator_InitBegin(NonceGenerator* p, secp256k1_hmac_sha256_t* pHMac, const char* szSalt, size_t nSalt)
{
	p->m_Counter = 0;
	p->m_FirstTime = 1;
	p->m_pContext = 0;
	p->m_nContext = 0;

	secp256k1_hmac_sha256_initialize(pHMac, (uint8_t*) szSalt, nSalt);
}

void NonceGenerator_InitEnd(NonceGenerator* p, secp256k1_hmac_sha256_t* pHMac)
{
	secp256k1_hmac_sha256_finalize(pHMac, p->m_Prk.m_pVal);
}

__stack_hungry__
void NonceGenerator_Init(NonceGenerator* p, const char* szSalt, size_t nSalt, const UintBig* pSeed)
{
	secp256k1_hmac_sha256_t hmac;

	NonceGenerator_InitBegin(p, &hmac, szSalt, nSalt);
	secp256k1_hmac_sha256_write(&hmac, pSeed->m_pVal, sizeof(pSeed->m_pVal));
	NonceGenerator_InitEnd(p, &hmac);
}

__stack_hungry__
void NonceGenerator_NextOkm(NonceGenerator* p)
{
	// Expand
	secp256k1_hmac_sha256_t hmac;
	secp256k1_hmac_sha256_initialize(&hmac, p->m_Prk.m_pVal, sizeof(p->m_Prk.m_pVal));

	if (p->m_FirstTime)
		p->m_FirstTime = 0;
	else
		secp256k1_hmac_sha256_write(&hmac, p->m_Okm.m_pVal, sizeof(p->m_Okm.m_pVal));

	secp256k1_hmac_sha256_write(&hmac, p->m_pContext, p->m_nContext);

	p->m_Counter++;
	secp256k1_hmac_sha256_write(&hmac, &p->m_Counter, sizeof(p->m_Counter));

	secp256k1_hmac_sha256_finalize(&hmac, p->m_Okm.m_pVal);
}

static int ScalarImportNnz(secp256k1_scalar* pS, const uint8_t* p)
{
	int overflow;
	secp256k1_scalar_set_b32(pS, p, &overflow);

	return !(overflow || secp256k1_scalar_is_zero(pS));
}

void NonceGenerator_NextScalar(NonceGenerator* p, secp256k1_scalar* pS)
{
	while (1)
	{
		NonceGenerator_NextOkm(p);
		if (ScalarImportNnz(pS, p->m_Okm.m_pVal))
			break;
	}
}

int memis0(const uint8_t* p, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

int IsUintBigZero(const UintBig* p)
{
	return memis0(p->m_pVal, sizeof(p->m_pVal));
}

//////////////////////////////
// Point
uint8_t Point_Compact_from_Ge_Ex(UintBig* pX, const secp256k1_ge* pGe)
{
	if (secp256k1_ge_is_infinity(pGe))
	{
		ZERO_OBJ(*pX);
		return 0;
	}

	secp256k1_fe_normalize((secp256k1_fe*) &pGe->x); // seems unnecessary, but ok
	secp256k1_fe_normalize((secp256k1_fe*) &pGe->y);

	secp256k1_fe_get_b32(pX->m_pVal, &pGe->x);
	return (secp256k1_fe_is_odd(&pGe->y) != 0);
}

void Point_Compact_from_Ge(CompactPoint* pCompact, const secp256k1_ge* pGe)
{
	pCompact->m_Y = Point_Compact_from_Ge_Ex(&pCompact->m_X, pGe);
}

void Point_Compact_from_Gej(CompactPoint* pCompact, const secp256k1_gej* pGej)
{
	secp256k1_ge ge;
	Point_Ge_from_Gej(&ge, pGej);
	Point_Compact_from_Ge(pCompact, &ge);
}

uint8_t Point_Compact_from_Gej_Ex(UintBig* pX, const secp256k1_gej* pGej)
{
	secp256k1_ge ge;
	Point_Ge_from_Gej(&ge, pGej);
	return Point_Compact_from_Ge_Ex(pX, &ge);
}

void Point_Gej_from_Ge(secp256k1_gej* pGej, const secp256k1_ge* pGe)
{
	secp256k1_gej_set_ge(pGej, pGe);
}

int Point_Ge_from_CompactNnz(secp256k1_ge* pGe, const CompactPoint* pCompact)
{
	if (pCompact->m_Y > 1)
		return 0; // not well-formed

	if (!secp256k1_fe_set_b32(&pGe->x, pCompact->m_X.m_pVal))
		return 0; // not well-formed

	if (!secp256k1_ge_set_xo_var(pGe, &pGe->x, pCompact->m_Y)) // according to code it seems ok to use ge.x as an argument
		return 0;

	return 1; // ok
}

int Point_Ge_from_Compact(secp256k1_ge* pGe, const CompactPoint* pCompact)
{
	if (!Point_Ge_from_CompactNnz(pGe, pCompact))
	{
		if (pCompact->m_Y || !IsUintBigZero(&pCompact->m_X))
			return 0;

		pGe->infinity = 1; // no specific function like secp256k1_ge_set_infinity
	}

	return 1;
}

void Point_Ge_from_Gej(secp256k1_ge* pGe, const secp256k1_gej* pGej)
{
	secp256k1_ge_set_gej_var(pGe, (secp256k1_gej*) pGej); // expensive, better to a batch convertion
}

void MulPoint(secp256k1_gej* pGej, const MultiMac_Secure* pGen, const secp256k1_scalar* pK)
{
	MultiMac_Context ctx;
	ctx.m_pRes = pGej;
	ctx.m_Fast.m_Count = 0;
	ctx.m_Secure.m_Count = 1;
	ctx.m_Secure.m_pGen = pGen;
	ctx.m_Secure.m_pK = pK;

	MultiMac_Calculate(&ctx);
}

void MulG(secp256k1_gej* pGej, const secp256k1_scalar* pK)
{
	MulPoint(pGej, Context_get()->m_pGenGJ, pK);
}

__stack_hungry__
void Sk2Pk(UintBig* pRes, secp256k1_scalar* pK)
{
	secp256k1_gej gej;
	MulG(&gej, pK);

	uint8_t y = Point_Compact_from_Gej_Ex(pRes, &gej);
	if (y)
		secp256k1_scalar_negate(pK, pK);
}
//////////////////////////////
// Oracle
void Oracle_Init(Oracle* p)
{
	secp256k1_sha256_initialize(&p->m_sha);
}

void Oracle_Expose(Oracle* p, const uint8_t* pPtr, size_t nSize)
{
	secp256k1_sha256_write(&p->m_sha, pPtr, nSize);
}

__stack_hungry__
void Oracle_NextHash(Oracle* p, UintBig* pHash)
{
	secp256k1_sha256_t sha = p->m_sha; // copy
	secp256k1_sha256_finalize(&sha, pHash->m_pVal);

	secp256k1_sha256_write(&p->m_sha, pHash->m_pVal, c_ECC_nBytes);
}

__stack_hungry__
void Oracle_NextScalar(Oracle* p, secp256k1_scalar* pS)
{
	while (1)
	{
		UintBig hash;
		Oracle_NextHash(p, &hash);

		if (ScalarImportNnz(pS, hash.m_pVal))
			break;
	}
}

void Oracle_NextPoint(Oracle* p, CompactPoint* pCompact, secp256k1_ge* pGe)
{
	pCompact->m_Y = 0;

	while (1)
	{
		Oracle_NextHash(p, &pCompact->m_X);

		if (Point_Ge_from_CompactNnz(pGe, pCompact))
			break;
	}
}

//////////////////////////////
// CoinID
#define c_CoinID_nSubkeyBits 24

int CoinID_getSchemeAndSubkey(const CoinID* p, uint8_t* pScheme, uint32_t* pSubkey)
{
	*pScheme = (uint8_t) (p->m_SubIdx >> c_CoinID_nSubkeyBits);
	*pSubkey = p->m_SubIdx & ((1U << c_CoinID_nSubkeyBits) - 1);

	if (!*pSubkey)
		return 0; // by convention: up to latest scheme, Subkey=0 - is a master key

	if (c_CoinID_Scheme_BB21 == *pScheme)
		return 0; // BB2.1 workaround

	return 1;
}

#define HASH_WRITE_STR(hash, str) secp256k1_sha256_write(&(hash), (const unsigned char*)str, sizeof(str))

void secp256k1_sha256_write_Num(secp256k1_sha256_t* pSha, uint64_t val)
{
	int nContinue;
	do
	{
		uint8_t x = (uint8_t)val;

		nContinue = (val >= 0x80);
		if (nContinue)
		{
			x |= 0x80;
			val >>= 7;
		}

		secp256k1_sha256_write(pSha, &x, sizeof(x));

	} while (nContinue);
}

void secp256k1_sha256_write_CompactPoint(secp256k1_sha256_t* pSha, const CompactPoint* pCompact)
{
	secp256k1_sha256_write(pSha, pCompact->m_X.m_pVal, sizeof(pCompact->m_X.m_pVal));
	secp256k1_sha256_write(pSha, &pCompact->m_Y, sizeof(pCompact->m_Y));
}

void secp256k1_sha256_write_CompactPointOptional2(secp256k1_sha256_t* pSha, const CompactPoint* pCompact, uint8_t bValid)
{
	secp256k1_sha256_write(pSha, &bValid, sizeof(bValid));
	if (bValid)
		secp256k1_sha256_write_CompactPoint(pSha, pCompact);
}

void secp256k1_sha256_write_CompactPointOptional(secp256k1_sha256_t* pSha, const CompactPoint* pCompact)
{
	secp256k1_sha256_write_CompactPointOptional2(pSha, pCompact, !!pCompact);
}

void secp256k1_sha256_write_CompactPointEx(secp256k1_sha256_t* pSha, const UintBig* pX, uint8_t nY)
{
	secp256k1_sha256_write(pSha, pX->m_pVal, sizeof(pX->m_pVal));

	nY &= 1;
	secp256k1_sha256_write(pSha, &nY, sizeof(nY));
}

__stack_hungry__
void secp256k1_sha256_write_Ge(secp256k1_sha256_t* pSha, const secp256k1_ge* pGe)
{
	CompactPoint pt;
	Point_Compact_from_Ge(&pt, pGe);

	secp256k1_sha256_write_CompactPoint(pSha, &pt);
}

void secp256k1_sha256_write_Gej_converted(secp256k1_sha256_t* pSha, const secp256k1_gej* pGej)
{
	secp256k1_sha256_write_Ge(pSha, (secp256k1_ge*) pGej);
}

void secp256k1_sha256_write_Gej(secp256k1_sha256_t* pSha, const secp256k1_gej* pGej) // expensive
{
	secp256k1_ge ge;
	Point_Ge_from_Gej(&ge, pGej);
	secp256k1_sha256_write_Ge(pSha, &ge);
}

__stack_hungry__
void CoinID_getHash(const CoinID* p, UintBig* pHash)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	uint8_t nScheme;
	uint32_t nSubkey;
	CoinID_getSchemeAndSubkey(p, &nScheme, &nSubkey);

	uint32_t nSubIdx = p->m_SubIdx;

	switch (nScheme)
	{
	case c_CoinID_Scheme_BB21:
		// this is actually V0, with a workaround
		nSubIdx = nSubkey | (c_CoinID_Scheme_V0 << c_CoinID_nSubkeyBits);
		nScheme = c_CoinID_Scheme_V0;
		// no break;

	case c_CoinID_Scheme_V0:
		HASH_WRITE_STR(sha, "kid");
		break;

	default:
		HASH_WRITE_STR(sha, "kidv-1");
	}

	secp256k1_sha256_write_Num(&sha, p->m_Idx);
	secp256k1_sha256_write_Num(&sha, p->m_Type);
	secp256k1_sha256_write_Num(&sha, nSubIdx);

	if (nScheme >= c_CoinID_Scheme_V1)
	{
		// newer scheme - account for the Value and Asset.
		secp256k1_sha256_write_Num(&sha, p->m_Amount);

		if (p->m_AssetID)
		{
			HASH_WRITE_STR(sha, "asset");
			secp256k1_sha256_write_Num(&sha, p->m_AssetID);
		}
	}

	secp256k1_sha256_finalize(&sha, pHash->m_pVal);
}

//////////////////////////////
// Kdf
__stack_hungry__
void Kdf_Init(Kdf* p, const UintBig* pSeed)
{
	static const char szSalt[] = "beam-HKdf";

	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), pSeed);

	static const char szCtx1[] = "gen";
	static const char szCtx2[] = "coF";

	ng.m_pContext = (const uint8_t*) szCtx1;
	ng.m_nContext = sizeof(szCtx1);

	NonceGenerator_NextOkm(&ng);
	p->m_Secret = ng.m_Okm;

	ng.m_Counter = 0;
	ng.m_FirstTime = 1;
	ng.m_pContext = (const uint8_t*) szCtx2;
	ng.m_nContext = sizeof(szCtx2);
	NonceGenerator_NextScalar(&ng, &p->m_kCoFactor);

	SECURE_ERASE_OBJ(ng);
}

__stack_hungry__
void Kdf_Derive_PKey_Pre(const Kdf* p, const UintBig* pHv, NonceGenerator* pN)
{
	static const char szSalt[] = "beam-Key";

	secp256k1_hmac_sha256_t hmac;
	NonceGenerator_InitBegin(pN, &hmac, szSalt, sizeof(szSalt));

	secp256k1_hmac_sha256_write(&hmac, p->m_Secret.m_pVal, sizeof(p->m_Secret.m_pVal));
	secp256k1_hmac_sha256_write(&hmac, pHv->m_pVal, sizeof(pHv->m_pVal));

	NonceGenerator_InitEnd(pN, &hmac);

	SECURE_ERASE_OBJ(hmac);
}

__stack_hungry__
void Kdf_Derive_PKey(const Kdf* p, const UintBig* pHv, secp256k1_scalar* pK)
{
	NonceGenerator ng;
	Kdf_Derive_PKey_Pre(p, pHv, &ng);

	NonceGenerator_NextScalar(&ng, pK);

	SECURE_ERASE_OBJ(ng);
}

void Kdf_Derive_SKey(const Kdf* p, const UintBig* pHv, secp256k1_scalar* pK)
{
	Kdf_Derive_PKey(p, pHv, pK);
	secp256k1_scalar_mul(pK, pK, &p->m_kCoFactor);
}

#define ARRAY_ELEMENT_SAFE(arr, index) ((arr)[(((index) < _countof(arr)) ? (index) : (_countof(arr) - 1))])
#define FOURCC_FROM_BYTES(a, b, c, d) (((((((uint32_t) a << 8) | (uint32_t) b) << 8) | (uint32_t) c) << 8) | (uint32_t) d)
#define FOURCC_FROM_STR(name) FOURCC_FROM_BYTES(ARRAY_ELEMENT_SAFE(#name,0), ARRAY_ELEMENT_SAFE(#name,1), ARRAY_ELEMENT_SAFE(#name,2), ARRAY_ELEMENT_SAFE(#name,3))

__stack_hungry__
void Kdf_getChild_Hv(uint32_t iChild, UintBig* pHv)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "kid");

	const uint32_t nType = FOURCC_FROM_STR(SubK);

	secp256k1_sha256_write_Num(&sha, iChild);
	secp256k1_sha256_write_Num(&sha, nType);
	secp256k1_sha256_write_Num(&sha, 0);

	secp256k1_sha256_finalize(&sha, pHv->m_pVal);
}

__stack_hungry__
void Kdf_getChild_Hv2(const Kdf* pParent, uint32_t iChild, UintBig* pHv)
{
	Kdf_getChild_Hv(iChild, pHv);

	secp256k1_scalar sk;
	Kdf_Derive_SKey(pParent, pHv, &sk);

	secp256k1_scalar_get_b32(pHv->m_pVal, &sk);
	SECURE_ERASE_OBJ(sk);
}

__stack_hungry__
void Kdf_getChild(Kdf* p, uint32_t iChild, const Kdf* pParent)
{
	UintBig hv;
	Kdf_getChild_Hv2(pParent, iChild, &hv);

	Kdf_Init(p, &hv);
	SECURE_ERASE_OBJ(hv);
}

//////////////////////////////
// Kdf - CoinID key derivation
__stack_hungry__
void CoinID_GetAssetGen(AssetID aid, secp256k1_ge* pGe)
{
	assert(aid);

	Oracle oracle;
	Oracle_Init(&oracle);

	HASH_WRITE_STR(oracle.m_sha, "B.Asset.Gen.V1");
	secp256k1_sha256_write_Num(&oracle.m_sha, aid);

	CompactPoint pt;
	Oracle_NextPoint(&oracle, &pt, pGe);
}

__stack_hungry__
void CoinID_GenerateAGen(AssetID aid, CustomGenerator* pAGen)
{
	assert(aid);

	static_assert(sizeof(*pAGen) >= sizeof(secp256k1_ge), "");

	CoinID_GetAssetGen(aid, (secp256k1_ge*) pAGen);
	MultiMac_Fast_Custom_Init(pAGen, (secp256k1_ge*) pAGen);
}

__stack_hungry__
void CoinID_getCommRawEx(const secp256k1_scalar* pkG, secp256k1_scalar* pkH, const CustomGenerator* pAGen, secp256k1_gej* pGej)
{
	MultiMac_WNaf wnaf;
	Context* pCtx = Context_get();

	// sk*G + v*H
	MultiMac_Context mmCtx;
	mmCtx.m_pRes = pGej;
	mmCtx.m_Secure.m_Count = 1;
	mmCtx.m_Secure.m_pK = pkG;
	mmCtx.m_Secure.m_pGen = pCtx->m_pGenGJ;
	mmCtx.m_Fast.m_Count = 1;
	mmCtx.m_Fast.m_pK = pkH;
	mmCtx.m_Fast.m_pWnaf = &wnaf;

	if (pAGen)
	{
		mmCtx.m_Fast.m_pGen0 = pAGen->m_pPt;
		mmCtx.m_Fast.m_WndBits = c_MultiMac_nBits_Custom;
		mmCtx.m_Fast.m_pZDenom = &pAGen->m_zDenom;
	}
	else
	{
		mmCtx.m_Fast.m_pGen0 = pCtx->m_pGenH;
		mmCtx.m_Fast.m_WndBits = c_MultiMac_nBits_H;
		mmCtx.m_Fast.m_pZDenom = 0;
	}

	MultiMac_Calculate(&mmCtx);
}

//__stack_hungry__
void CoinID_getCommRaw(const secp256k1_scalar* pK, Amount amount, const CustomGenerator* pAGen, secp256k1_gej* pGej)
{
	secp256k1_scalar kH;
	secp256k1_scalar_set_u64(&kH, amount);
	CoinID_getCommRawEx(pK, &kH, pAGen, pGej);
}

void CoinID_getSk(const Kdf* pKdf, const CoinID* pCid, secp256k1_scalar* pK)
{
	CoinID_getSkComm(pKdf, pCid, pK, 0);
}

__stack_hungry__
static void CoinID_getSkNonSwitch(const Kdf* pKdf, const CoinID* pCid, secp256k1_scalar* pK)
{
	uint8_t nScheme;
	uint32_t nSubkey;
	UintBig hv;
	Kdf kdfC;

	int nChild = CoinID_getSchemeAndSubkey(pCid, &nScheme, &nSubkey);
	if (nChild)
	{
		Kdf_getChild(&kdfC, nSubkey, pKdf);
		pKdf = &kdfC;
	}

	CoinID_getHash(pCid, &hv);
	Kdf_Derive_SKey(pKdf, &hv, pK);

	if (nChild)
		SECURE_ERASE_OBJ(kdfC);
}

__stack_hungry__
static void CoinID_getSkSwitchDelta(secp256k1_scalar* pK, const secp256k1_gej* pCommsNorm)
{
	Oracle oracle;
	Oracle_Init(&oracle);

	secp256k1_sha256_write_Gej_converted(&oracle.m_sha, pCommsNorm);
	secp256k1_sha256_write_Gej_converted(&oracle.m_sha, pCommsNorm + 1);

	Oracle_NextScalar(&oracle, pK);
}

__stack_hungry__
static void CoinID_getSkComm_FromNonSwitchK(const CoinID* pCid, secp256k1_scalar* pK, CompactPoint* pComm, const CustomGenerator* pAGen)
{
	secp256k1_gej pGej[2];

	CoinID_getCommRaw(pK, pCid->m_Amount, pAGen, pGej); // sk*G + amount*H(aid)
	MulPoint(pGej + 1, Context_get()->m_pGenGJ + 1, pK); // sk*J

	Point_Gej_2_Normalize(pGej);

	secp256k1_scalar kDelta;
	CoinID_getSkSwitchDelta(&kDelta, pGej);

	secp256k1_scalar_add(pK, pK, &kDelta);

	if (pComm)
	{
		MulG(pGej + 1, &kDelta);

		// pGej[0] is ge

		wrap_gej_add_ge_var(pGej + 1, pGej + 1, (secp256k1_ge*) pGej);
		Point_Compact_from_Gej(pComm, pGej + 1);
	}
}

__stack_hungry__
void CoinID_getSkComm(const Kdf* pKdf, const CoinID* pCid, secp256k1_scalar* pK, CompactPoint* pComm)
{
	CoinID_getSkNonSwitch(pKdf, pCid, pK);

	CustomGenerator aGen;
	if (pCid->m_AssetID)
		CoinID_GenerateAGen(pCid->m_AssetID, &aGen);

	CoinID_getSkComm_FromNonSwitchK(pCid, pK, pComm, pCid->m_AssetID ? &aGen : 0);
}

__stack_hungry__
static void ShieldedInput_getSk(const KeyKeeper* p, const ShieldedInput_Blob* pInpBlob, const ShieldedInput_Fmt* pInpFmt, secp256k1_scalar* pK)
{
	UintBig hv;
	secp256k1_sha256_t sha;

	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "sh.skout");
	secp256k1_sha256_write_Num(&sha, pInpFmt->m_Amount);
	secp256k1_sha256_write_Num(&sha, pInpFmt->m_AssetID);
	secp256k1_sha256_write_Num(&sha, pInpFmt->m_Fee);
	secp256k1_sha256_write(&sha, pInpBlob->m_kSerG.m_pVal, sizeof(pInpBlob->m_kSerG.m_pVal));
	secp256k1_sha256_write_Num(&sha, !!pInpBlob->m_IsCreatedByViewer);
	secp256k1_sha256_write_Num(&sha, pInpFmt->m_nViewerIdx);
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	Kdf kdfChild;
	Kdf_getChild(&kdfChild, c_ShieldedInput_ChildKdf, &p->m_MasterKey);
	Kdf_Derive_SKey(&kdfChild, &hv, pK);
}

//////////////////////////////
// RangeProof
typedef struct
{
	NonceGenerator m_NonceGen; // 88 bytes
	secp256k1_gej m_pGej[2]; // 248 bytes

	// 97 bytes. This can be saved, at expense of calculating them again (CoinID_getSkComm)
	secp256k1_scalar m_sk;
	secp256k1_scalar m_alpha;
	CompactPoint m_Commitment;

} RangeProof_Worker;

__stack_hungry__
static void RangeProof_Calculate_Before_S(RangeProof* const p, RangeProof_Worker* const pWrk)
{
	Oracle oracle;
	UintBig hv;
	secp256k1_scalar k;

	// get seed
	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pWrk->m_Commitment);
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);

	Kdf_Derive_PKey(p->m_pKdf, &hv, &k);
	secp256k1_scalar_get_b32(hv.m_pVal, &k);

	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write(&oracle.m_sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);

	// NonceGen
	static const char szSalt[] = "bulletproof";
	NonceGenerator_Init(&pWrk->m_NonceGen, szSalt, sizeof(szSalt), &hv);

	NonceGenerator_NextScalar(&pWrk->m_NonceGen, &pWrk->m_alpha); // alpha

	// embed params into alpha
#pragma pack (push, 1)
	typedef struct
	{
		uint32_t m_Padding;
		AssetID m_AssetID;
		uint64_t m_Idx;
		uint32_t m_Type;
		uint32_t m_SubIdx;
		Amount m_Amount;
	} RangeProof_Embedded;
#pragma pack (pop)

	static_assert(sizeof(RangeProof_Embedded) == c_ECC_nBytes, "");
	RangeProof_Embedded* pEmb = (RangeProof_Embedded*) hv.m_pVal;

	pEmb->m_Amount = bswap64_be(p->m_Cid.m_Amount);
	pEmb->m_SubIdx = bswap32_be(p->m_Cid.m_SubIdx);
	pEmb->m_Type = bswap32_be(p->m_Cid.m_Type);
	pEmb->m_Idx = bswap64_be(p->m_Cid.m_Idx);
	pEmb->m_AssetID = bswap32_be(p->m_Cid.m_AssetID);
	pEmb->m_Padding = 0;

	int overflow;
	secp256k1_scalar_set_b32(&k, hv.m_pVal, &overflow);
	assert(!overflow);

	secp256k1_scalar_add(&pWrk->m_alpha, &pWrk->m_alpha, &k);
}

__stack_hungry__
static void RangeProof_Calculate_S(RangeProof* const p, RangeProof_Worker* const pWrk)
{
	// Data buffers needed for calculating Part1.S
	// Need to multi-exponentiate nDims * 2 == 128 elements.
	// Calculating everything in a single pass is faster, but requires more buffers (stack memory)
	// Each element size is sizeof(secp256k1_scalar) + sizeof(MultiMac_WNaf) == 34 bytes
	//
	// This requires of 4.25K stack memory
#define nDims (sizeof(Amount) * 8)
#define Calc_S_Naggle_Max (nDims * 2)

#ifdef BeamCrypto_ScarceStack
#	define Calc_S_Naggle 22 // would take 6 iterations
#else // BeamCrypto_ScarceStack
#	define Calc_S_Naggle Calc_S_Naggle_Max // use max
#endif // BeamCrypto_ScarceStack

	static_assert(Calc_S_Naggle <= Calc_S_Naggle_Max, "Naggle too large");

	secp256k1_scalar pS[Calc_S_Naggle];
	MultiMac_WNaf pWnaf[Calc_S_Naggle];

	secp256k1_scalar* const pRho = (secp256k1_scalar*) (pWrk->m_pGej + (Calc_S_Naggle < Calc_S_Naggle_Max)); // reuse its mem
	// depending on naggling, the 1st point would be either pGej o pGej+1, hence we may use the other one

	NonceGenerator_NextScalar(&pWrk->m_NonceGen, pRho);

	MultiMac_Context mmCtx;

	mmCtx.m_Secure.m_Count = 1;
	mmCtx.m_Secure.m_pK = pRho;
	mmCtx.m_Secure.m_pGen = Context_get()->m_pGenGJ;

	mmCtx.m_Fast.m_pZDenom = 0;
	mmCtx.m_Fast.m_Count = 0;
	mmCtx.m_Fast.m_WndBits = c_MultiMac_nBits_Rangeproof;
	mmCtx.m_Fast.m_pK = pS;
	mmCtx.m_Fast.m_pWnaf = pWnaf;

#ifdef BeamCrypto_SlowLoad
	secp256k1_ge_storage pGen[Calc_S_Naggle][c_MultiMac_OddCount(c_MultiMac_nBits_Rangeproof)];
	memcpy(pGen, Context_get()->m_pGenRangeproof, sizeof(pGen));
	mmCtx.m_Fast.m_pGen0 = pGen[0];
#else // BeamCrypto_SlowLoad
	mmCtx.m_Fast.m_pGen0 = Context_get()->m_pGenRangeproof[0];
#endif // BeamCrypto_SlowLoad

	for (unsigned int iBit = 0; iBit < nDims * 2; iBit++, mmCtx.m_Fast.m_Count++)
	{
		if (Calc_S_Naggle == mmCtx.m_Fast.m_Count)
		{
			// flush
			mmCtx.m_pRes = pWrk->m_pGej + (iBit != Calc_S_Naggle); // 1st flush goes to pGej[0] directly
			MultiMac_Calculate(&mmCtx);

			if (iBit != Calc_S_Naggle)
				wrap_gej_add_var(pWrk->m_pGej, pWrk->m_pGej + 1, pWrk->m_pGej);

			mmCtx.m_Secure.m_Count = 0;
			mmCtx.m_Fast.m_Count = 0;

#ifdef BeamCrypto_SlowLoad
			uint32_t nRemaining = min(Calc_S_Naggle, (nDims * 2 - iBit));
			memcpy(pGen, Context_get()->m_pGenRangeproof + iBit, sizeof(pGen[0]) * nRemaining);
#else // BeamCrypto_SlowLoad
			mmCtx.m_Fast.m_pGen0 += Calc_S_Naggle * c_MultiMac_OddCount(c_MultiMac_nBits_Rangeproof);
#endif // BeamCrypto_SlowLoad

		}

		NonceGenerator_NextScalar(&pWrk->m_NonceGen, pS + mmCtx.m_Fast.m_Count);

		if (!(iBit % nDims) && p->m_pKExtra)
		{
			// embed more info
			int overflow;
			secp256k1_scalar_set_b32(p->m_pTauX, p->m_pKExtra[iBit / nDims].m_pVal, &overflow);
			wrap_scalar_add(pS + mmCtx.m_Fast.m_Count, pS + mmCtx.m_Fast.m_Count, p->m_pTauX);
		}
	}

	mmCtx.m_pRes = pWrk->m_pGej + 1;
	MultiMac_Calculate(&mmCtx);

	if (Calc_S_Naggle < Calc_S_Naggle_Max)
		wrap_gej_add_var(pWrk->m_pGej + 1, pWrk->m_pGej + 1, pWrk->m_pGej);
}

static void RangeProof_Calculate_A_Bits(secp256k1_gej* pRes, secp256k1_ge* pGeTmp, Amount v)
{
	Context* pCtx = Context_get();
	for (uint32_t i = 0; i < nDims; i++)
	{
		if (1 & (v >> i))
			secp256k1_ge_from_storage(pGeTmp, pCtx->m_pGenRangeproof[i]);
		else
		{
			secp256k1_ge_from_storage(pGeTmp, pCtx->m_pGenRangeproof[nDims + i]);
			secp256k1_ge_neg(pGeTmp, pGeTmp);
		}

		wrap_gej_add_ge_var(pRes, pRes, pGeTmp);
	}
}

__stack_hungry__
static int RangeProof_Calculate_After_S(RangeProof* const p, RangeProof_Worker* const pWrk)
{
	{
		// CalcA
		MulG(pWrk->m_pGej, &pWrk->m_alpha); // alpha*G

		secp256k1_ge geTmp;
		RangeProof_Calculate_A_Bits(pWrk->m_pGej, &geTmp, p->m_Cid.m_Amount);
	}

	// normalize A,S at once, feed them to Oracle, get the challenges
	Point_Gej_2_Normalize(pWrk->m_pGej);

	secp256k1_scalar pK[2];

	Oracle oracle;
	Oracle_Init(&oracle);
	secp256k1_sha256_write_Num(&oracle.m_sha, 0); // incubation time, must be zero
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pWrk->m_Commitment); // starting from Fork1, earlier schem is not allowed
	secp256k1_sha256_write_CompactPointOptional(&oracle.m_sha, p->m_pAssetGen); // starting from Fork3, earlier schem is not allowed

	for (unsigned int i = 0; i < 2; i++)
		secp256k1_sha256_write_Gej_converted(&oracle.m_sha, pWrk->m_pGej + i);

	for (unsigned int i = 0; i < 2; i++)
		Oracle_NextScalar(&oracle, pK + i); // challenges y,z. The 'y' is not needed

	{
		// Use the challenges, sk, T1 and T2 to init the NonceGen for blinding the sk
		static const char szSalt[] = "bulletproof-sk";

		secp256k1_hmac_sha256_t hmac;
		NonceGenerator_InitBegin(&pWrk->m_NonceGen, &hmac, szSalt, sizeof(szSalt));

		UintBig hv;
		secp256k1_scalar_get_b32(hv.m_pVal, &pWrk->m_sk);
		secp256k1_hmac_sha256_write(&hmac, hv.m_pVal, sizeof(hv.m_pVal));

		for (unsigned int i = 0; i < 2; i++)
		{
			secp256k1_hmac_sha256_write(&hmac, p->m_pT_In[i].m_X.m_pVal, sizeof(p->m_pT_In[i].m_X.m_pVal));
			secp256k1_hmac_sha256_write(&hmac, &p->m_pT_In[i].m_Y, sizeof(p->m_pT_In[i].m_Y));

			secp256k1_scalar_get_b32(hv.m_pVal, pK + i);
			secp256k1_hmac_sha256_write(&hmac, hv.m_pVal, sizeof(hv.m_pVal));
		}

		NonceGenerator_InitEnd(&pWrk->m_NonceGen, &hmac);
	}

	int ok = 1;

	secp256k1_scalar zChallenge = pK[1];

	for (unsigned int i = 0; i < 2; i++)
	{
		NonceGenerator_NextScalar(&pWrk->m_NonceGen, pK + i); // tau1/2

		MulG(pWrk->m_pGej + i, pK + i); // pub nonces of T1/T2

		secp256k1_ge ge;
		if (!Point_Ge_from_Compact(&ge, p->m_pT_In + i))
		{
			ok = 0;
			break;
		}

		wrap_gej_add_ge_var(pWrk->m_pGej + i, pWrk->m_pGej + i, &ge);
	}

	SECURE_ERASE_OBJ(pWrk->m_NonceGen);

	if (ok)
	{
		// normalize & expose
		Point_Gej_2_Normalize(pWrk->m_pGej);

		for (unsigned int i = 0; i < 2; i++)
		{
			Point_Compact_from_Ge(p->m_pT_Out + i, (secp256k1_ge*) (pWrk->m_pGej + i));
			secp256k1_sha256_write_CompactPoint(&oracle.m_sha, p->m_pT_Out + i);
		}

		// last challenge
		secp256k1_scalar xChallenge;
		Oracle_NextScalar(&oracle, &xChallenge);

		// m_TauX = tau2*x^2 + tau1*x + sk*z^2
		secp256k1_scalar_mul(pK, pK, &xChallenge); // tau1*x
		secp256k1_scalar_mul(&xChallenge, &xChallenge, &xChallenge); // x^2
		secp256k1_scalar_mul(pK + 1, pK + 1, &xChallenge); // tau2*x^2

		secp256k1_scalar_mul(&zChallenge, &zChallenge, &zChallenge); // z^2

		secp256k1_scalar_mul(p->m_pTauX, &pWrk->m_sk, &zChallenge); // sk*z^2
		secp256k1_scalar_add(p->m_pTauX, p->m_pTauX, pK);
		secp256k1_scalar_add(p->m_pTauX, p->m_pTauX, pK + 1);
	}

	SECURE_ERASE_OBJ(pWrk->m_sk);
	SECURE_ERASE_OBJ(pK); // tau1/2
	//SECURE_ERASE_OBJ(hv); - no need, last value is the challenge

	return ok;
}

__stack_hungry__
int RangeProof_Calculate(RangeProof* p)
{
	RangeProof_Worker wrk;

	CoinID_getSkComm(p->m_pKdf, &p->m_Cid, &wrk.m_sk, &wrk.m_Commitment);

	RangeProof_Calculate_Before_S(p, &wrk);
	RangeProof_Calculate_S(p, &wrk);

	return RangeProof_Calculate_After_S(p, &wrk);
}

typedef struct
{
	// in
	UintBig m_SeedGen;
	const UintBig* m_pSeedSk;
	uint32_t m_nUser; // has to be no bigger than c_ECC_nBytes - sizeof(Amount). If less - zero-padding is verified
	// out
	void* m_pUser;
	Amount m_Amount;

	secp256k1_scalar* m_pSk;
	secp256k1_scalar* m_pExtra;

} RangeProof_Recovery_Context;

__stack_hungry__
static int RangeProof_Recover(const RangeProof_Packed* pRangeproof, Oracle* pOracle, RangeProof_Recovery_Context* pCtx)
{
	static const char szSalt[] = "bulletproof";
	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &pCtx->m_SeedGen);

	secp256k1_scalar alpha_minus_params, ro, x, y, z, tmp;
	NonceGenerator_NextScalar(&ng, &alpha_minus_params);
	NonceGenerator_NextScalar(&ng, &ro);

	// oracle << p1.A << p1.S
	// oracle >> y, z
	// oracle << p2.T1 << p2.T2
	// oracle >> x
	secp256k1_sha256_write_CompactPointEx(&pOracle->m_sha, &pRangeproof->m_Ax, pRangeproof->m_pYs[1] >> 4);
	secp256k1_sha256_write_CompactPointEx(&pOracle->m_sha, &pRangeproof->m_Sx, pRangeproof->m_pYs[1] >> 5);
	Oracle_NextScalar(pOracle, &y);
	Oracle_NextScalar(pOracle, &z);
	secp256k1_sha256_write_CompactPointEx(&pOracle->m_sha, &pRangeproof->m_T1x, pRangeproof->m_pYs[1] >> 6);
	secp256k1_sha256_write_CompactPointEx(&pOracle->m_sha, &pRangeproof->m_T2x, pRangeproof->m_pYs[1] >> 7);
	Oracle_NextScalar(pOracle, &x);

	// m_Mu = alpha + ro*x
	// alpha = m_Mu - ro*x = alpha_minus_params + params
	// params = m_Mu - ro*x - alpha_minus_params
	secp256k1_scalar_mul(&ro, &ro, &x);
	secp256k1_scalar_add(&tmp, &alpha_minus_params, &ro);
	secp256k1_scalar_negate(&tmp, &tmp); // - ro*x - alpha_minus_params

	int overflow;
	secp256k1_scalar_set_b32(&ro, pRangeproof->m_Mu.m_pVal, &overflow);
	if (overflow)
		return 0;

	secp256k1_scalar_add(&tmp, &tmp, &ro);

	{
		static_assert(sizeof(ro) >= c_ECC_nBytes, "");
		uint8_t* pBlob = (uint8_t*) &ro; // just reuse this mem

		secp256k1_scalar_get_b32(pBlob, &tmp);

		assert(pCtx->m_nUser <= c_ECC_nBytes - sizeof(Amount));
		uint32_t nPad = c_ECC_nBytes - sizeof(Amount) - pCtx->m_nUser;

		if (!memis0(pBlob, nPad))
			return 0;

		memcpy(pCtx->m_pUser, pBlob + nPad, pCtx->m_nUser);

		// recover value. It's always at the buf end
		pCtx->m_Amount = bswap64_be(*(Amount*) (pBlob + c_ECC_nBytes - sizeof(Amount)));
	}

	secp256k1_scalar_add(&alpha_minus_params, &alpha_minus_params, &tmp); // just alpha

	// Recalculate p1.A, make sure we get the correct result
	union {
		secp256k1_gej comm;
		CompactPoint pt;
	} u;

	secp256k1_ge ge;
	MulG(&u.comm, &alpha_minus_params);
	RangeProof_Calculate_A_Bits(&u.comm, &ge, pCtx->m_Amount);

	Point_Ge_from_Gej(&ge, &u.comm);
	Point_Compact_from_Ge(&u.pt, &ge);

	if (memcmp(u.pt.m_X.m_pVal, pRangeproof->m_Ax.m_pVal, c_ECC_nBytes) || (u.pt.m_Y != (1 & (pRangeproof->m_pYs[1] >> 4))))
		return 0; // false positive

	if (pCtx->m_pSeedSk || pCtx->m_pExtra)
		secp256k1_scalar_mul(&tmp, &z, &z); // z^2

	if (pCtx->m_pSeedSk)
	{
		assert(pCtx->m_pSk);

		secp256k1_scalar_set_b32(pCtx->m_pSk, pRangeproof->m_Taux.m_pVal, &overflow);

		// recover the blinding factor
		{
			static const char szSaltSk[] = "bp-key";
			NonceGenerator ngSk;
			NonceGenerator_Init(&ngSk, szSaltSk, sizeof(szSaltSk), pCtx->m_pSeedSk);
			NonceGenerator_NextScalar(&ngSk, &alpha_minus_params); // tau1
			NonceGenerator_NextScalar(&ngSk, &ro); // tau2
		}

		secp256k1_scalar_mul(&ro, &ro, &x);
		secp256k1_scalar_add(&ro, &ro, &alpha_minus_params);
		secp256k1_scalar_mul(&ro, &ro, &x); // tau2*x^2 + tau1*x

		secp256k1_scalar_negate(&ro, &ro);
		secp256k1_scalar_add(pCtx->m_pSk, pCtx->m_pSk, &ro);

		secp256k1_scalar_inverse(&ro, &tmp); // heavy operation
		secp256k1_scalar_mul(pCtx->m_pSk, pCtx->m_pSk, &ro);
	}

	if (pCtx->m_pExtra)
	{
		secp256k1_scalar pE[2][_countof(pRangeproof->m_pLRx)];

		secp256k1_sha256_write(&pOracle->m_sha, pRangeproof->m_tDot.m_pVal, sizeof(pRangeproof->m_tDot.m_pVal));
		Oracle_NextScalar(pOracle, &ro); // dot-multiplier, unneeded atm

		for (uint32_t iCycle = 0; iCycle < _countof(pRangeproof->m_pLRx); iCycle++)
		{
			Oracle_NextScalar(pOracle, pE[0] + iCycle); // challenge
			secp256k1_scalar_inverse(pE[1] + iCycle, pE[0] + iCycle);

			for (uint32_t j = 0; j < 2; j++)
			{
				uint32_t iBit = (iCycle << 1) + j;
				secp256k1_sha256_write_CompactPointEx(&pOracle->m_sha, pRangeproof->m_pLRx[iCycle] + j, pRangeproof->m_pYs[iBit >> 3] >> (7 & iBit));
			}
		}

		secp256k1_scalar yPwr;
		secp256k1_scalar_set_int(&yPwr, 1);
		secp256k1_scalar_set_int(&alpha_minus_params, 2);

		secp256k1_scalar_negate(&ro, &yPwr);
		secp256k1_scalar_add(&ro, &ro, &z);
		const secp256k1_scalar* pZ[] = { &z, &ro }; // z, z-1

		// tmp == z^2

		static_assert(!(nDims & 1), ""); // must be even
		secp256k1_scalar pS[nDims / 2]; // 32 elements, 1K stack size. Perform 1st condensation in-place (otherwise we'd need to prepare 64 elements first)

		for (unsigned int j = 0; j < 2; j++)
		{
			for (uint32_t i = 0; i < nDims; i++)
			{
				secp256k1_scalar val;
				NonceGenerator_NextScalar(&ng, &val);

				uint32_t bit = 1 & (pCtx->m_Amount >> i);
				secp256k1_scalar tmp2;

				if (j)
				{
					secp256k1_scalar_mul(&val, &val, &x); // pS[i] *= x;
					secp256k1_scalar_mul(&val, &val, &yPwr); // pS[i] *= yPwr;

					secp256k1_scalar_mul(&tmp2, pZ[!bit], &yPwr);
					secp256k1_scalar_add(&tmp2, &tmp2, &tmp);
					secp256k1_scalar_add(&val, &val, &tmp2); // pS[i] += pZ[!bit]*yPwr + z^2*2^i

					secp256k1_scalar_mul(&tmp, &tmp, &alpha_minus_params); // x2
					secp256k1_scalar_mul(&yPwr, &yPwr, &y);
				}
				else
				{
					secp256k1_scalar_mul(&val, &val, &x); // pS[i] *= x;

					secp256k1_scalar_negate(&tmp2, pZ[bit]);
					secp256k1_scalar_add(&val, &val, &tmp2); // pS[i] -= pZ[bit];
				}

				// 1st condensation in-place
				if (i < nDims / 2)
					secp256k1_scalar_mul(pS + i, &val, pE[j]);
				else
				{
					secp256k1_scalar_mul(&val, &val, pE[!j]);
					secp256k1_scalar_add(pS + i - nDims / 2, pS + i - nDims / 2, &val);
				}
			}

			// all other condensation cycles
			uint32_t nStep = nDims / 2;
			for (uint32_t iCycle = 1; iCycle < _countof(pRangeproof->m_pLRx); iCycle++)
			{
				nStep >>= 1;
				assert(nStep);

				for (uint32_t i = 0; i < nStep; i++)
				{
					secp256k1_scalar_mul(pS + i, pS + i, pE[j] + iCycle);
					secp256k1_scalar_mul(pS + nStep + i, pS + nStep + i, pE[!j] + iCycle);
					secp256k1_scalar_add(pS + i, pS + i, pS + nStep + i);
				}

			}
			assert(1 == nStep);

			secp256k1_scalar_set_b32(pS + 1, pRangeproof->m_pCondensed[j].m_pVal, &overflow);
			secp256k1_scalar_negate(pS, pS);
			secp256k1_scalar_add(pS, pS, pS + 1); // the difference

			// now let's estimate the difference that would be if extra == 1.
			pS[1] = x;
			for (uint32_t iCycle = 0; iCycle < _countof(pRangeproof->m_pLRx); iCycle++)
				secp256k1_scalar_mul(pS + 1, pS + 1, pE[j] + iCycle);

			secp256k1_scalar_inverse(pCtx->m_pExtra + j, pS + 1);
			secp256k1_scalar_mul(pCtx->m_pExtra + j, pCtx->m_pExtra + j, pS);
		}
	}

	return 1;
}

//////////////////////////////
// Signature
__stack_hungry__
void Signature_GetChallengeEx(const CompactPoint* pNoncePub, const UintBig* pMsg, secp256k1_scalar* pE)
{
	Oracle oracle;
	Oracle_Init(&oracle);
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, pNoncePub);
	secp256k1_sha256_write(&oracle.m_sha, pMsg->m_pVal, sizeof(pMsg->m_pVal));

	Oracle_NextScalar(&oracle, pE);
}

void Signature_GetChallenge(const Signature* p, const UintBig* pMsg, secp256k1_scalar* pE)
{
	Signature_GetChallengeEx(&p->m_NoncePub, pMsg, pE);
}

__stack_hungry__
void Signature_Sign(Signature* p, const UintBig* pMsg, const secp256k1_scalar* pSk)
{
	// get nonce
	union {
		secp256k1_hmac_sha256_t hmac;
		secp256k1_gej gej;
	} u2;

	NonceGenerator ng;
	static const char szSalt[] = "beam-Schnorr";
	NonceGenerator_InitBegin(&ng, &u2.hmac, szSalt, sizeof(szSalt));

	union
	{
		UintBig sk;
		secp256k1_scalar nonce;
	} u;

	static_assert(sizeof(u.nonce) >= sizeof(u.sk), ""); // means nonce completely overwrites the sk

	secp256k1_scalar_get_b32(u.sk.m_pVal, pSk);
	secp256k1_hmac_sha256_write(&u2.hmac, u.sk.m_pVal, sizeof(u.sk.m_pVal));
	secp256k1_hmac_sha256_write(&u2.hmac, pMsg->m_pVal, sizeof(pMsg->m_pVal));

	NonceGenerator_InitEnd(&ng, &u2.hmac);
	NonceGenerator_NextScalar(&ng, &u.nonce);
	SECURE_ERASE_OBJ(ng);

	// expose the nonce
	MulG(&u2.gej, &u.nonce);

	Point_Compact_from_Gej(&p->m_NoncePub, &u2.gej);

	Signature_SignPartial(p, pMsg, pSk, &u.nonce);

	SECURE_ERASE_OBJ(u.nonce);
}

__stack_hungry__
void Signature_SignPartialEx(UintBig* pRes, const secp256k1_scalar* pE, const secp256k1_scalar* pSk, const secp256k1_scalar* pNonce)
{
	secp256k1_scalar k;
	secp256k1_scalar_mul(&k, pE, pSk);
	secp256k1_scalar_add(&k, &k, pNonce);
	secp256k1_scalar_negate(&k, &k);

	secp256k1_scalar_get_b32(pRes->m_pVal, &k);
}

__stack_hungry__
void Signature_SignPartial(Signature* p, const UintBig* pMsg, const secp256k1_scalar* pSk, const secp256k1_scalar* pNonce)
{
	secp256k1_scalar e;
	Signature_GetChallenge(p, pMsg, &e);
	Signature_SignPartialEx(&p->m_k, &e, pSk, pNonce);
}

__stack_hungry__
static int Signature_IsValid_Internal(const Signature* p, const UintBig* pMsg, const CustomGenerator* pPkGen)
{
	secp256k1_gej gej;

	union
	{
		struct {
			secp256k1_scalar k;
			secp256k1_scalar s;
			int overflow;
			MultiMac_WNaf wnaf;
		} p1;

		secp256k1_ge geNonce;
	} u;

	// for historical reasons we don't check for overflow, i.e. theoretically there can be an ambiguity, but it makes not much sense for the attacker
	secp256k1_scalar_set_b32(&u.p1.k, p->m_k.m_pVal, &u.p1.overflow);

	MultiMac_Context ctx;
	ctx.m_pRes = &gej;
	ctx.m_Secure.m_Count = 1;
	ctx.m_Secure.m_pGen = Context_get()->m_pGenGJ;
	ctx.m_Secure.m_pK = &u.p1.k;

	if (!pPkGen)
		// unlikely, but allowed for historical reasons
		ctx.m_Fast.m_Count = 0;
	else
	{
		ctx.m_Fast.m_Count = 1;
		ctx.m_Fast.m_pZDenom = &pPkGen->m_zDenom;
		ctx.m_Fast.m_pGen0 = pPkGen->m_pPt;
		ctx.m_Fast.m_WndBits = c_MultiMac_nBits_Custom;
		ctx.m_Fast.m_pK = &u.p1.s;
		ctx.m_Fast.m_pWnaf = &u.p1.wnaf;

		Signature_GetChallenge(p, pMsg, &u.p1.s);
	}

	MultiMac_Calculate(&ctx);

	if (!Point_Ge_from_Compact(&u.geNonce, &p->m_NoncePub))
		return 0; // bad pub nonce

	wrap_gej_add_ge_var(&gej, &gej, &u.geNonce);

	return secp256k1_gej_is_infinity(&gej);
}

__stack_hungry__
int Signature_IsValid(const Signature* p, const UintBig* pMsg, const CompactPoint* pPk)
{
	CustomGenerator gen; // very large

	static_assert(sizeof(gen) >= sizeof(secp256k1_ge), "");
	secp256k1_ge* const pGe = (secp256k1_ge*)&gen;

	if (!Point_Ge_from_Compact(pGe, pPk))
		return 0; // bad Pubkey

	if (secp256k1_ge_is_infinity(pGe))
		return Signature_IsValid_Internal(p, pMsg, 0);

	MultiMac_Fast_Custom_Init(&gen, pGe);

	return Signature_IsValid_Internal(p, pMsg, &gen);
}

__stack_hungry__
static int Signature_IsValid_Ex(const Signature* p, const UintBig* pMsg, const UintBig* pPeer)
{
	CompactPoint pt;
	pt.m_X = *pPeer;
	pt.m_Y = 0;

	return Signature_IsValid(p, pMsg, &pt);
}


//////////////////////////////
// TxKernel
__stack_hungry__
void TxKernel_getID_Ex(const TxKernelUser* pUser, const TxKernelCommitments* pComms, UintBig* pMsg, const UintBig* pNestedIDs, uint32_t nNestedIDs)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	secp256k1_sha256_write_Num(&sha, pUser->m_Fee);
	secp256k1_sha256_write_Num(&sha, pUser->m_hMin);
	secp256k1_sha256_write_Num(&sha, pUser->m_hMax);

	secp256k1_sha256_write_CompactPoint(&sha, &pComms->m_Commitment);
	secp256k1_sha256_write_Num(&sha, 0); // former m_AssetEmission

	uint8_t nFlags = 0; // extended flags, irrelevent for HW wallet
	secp256k1_sha256_write(&sha, &nFlags, sizeof(nFlags));

	for (uint32_t i = 0; i < nNestedIDs; i++)
	{
		secp256k1_sha256_write(&sha, &nFlags, sizeof(nFlags));
		secp256k1_sha256_write(&sha, pNestedIDs[i].m_pVal, sizeof(pNestedIDs[i].m_pVal));
	}

	nFlags = 1; // no more nested kernels
	secp256k1_sha256_write(&sha, &nFlags, sizeof(nFlags));

	secp256k1_sha256_finalize(&sha, pMsg->m_pVal);
}

void TxKernel_getID(const TxKernelUser* pUser, const TxKernelCommitments* pComms, UintBig* pMsg)
{
	TxKernel_getID_Ex(pUser, pComms, pMsg, 0, 0);
}

__stack_hungry__
int TxKernel_IsValid(const TxKernelUser* pUser, const TxKernelCommitments* pComms, const UintBig* pSig)
{
	UintBig msg;
	TxKernel_getID(pUser, pComms, &msg);

	Signature sig;
	sig.m_NoncePub = pComms->m_NoncePub;
	sig.m_k = *pSig;


	return Signature_IsValid(&sig, &msg, &pComms->m_Commitment);
}

__stack_hungry__
void TxKernel_SpecialMsg(secp256k1_sha256_t* pSha, Amount fee, Height hMin, Height hMax, uint8_t nType)
{
	// calculate kernel Msg
	secp256k1_sha256_initialize(pSha);
	secp256k1_sha256_write_Num(pSha, fee);
	secp256k1_sha256_write_Num(pSha, hMin);
	secp256k1_sha256_write_Num(pSha, hMax);

	UintBig hv = { 0 };
	secp256k1_sha256_write(pSha, hv.m_pVal, sizeof(hv.m_pVal));
	hv.m_pVal[0] = 1;
	secp256k1_sha256_write(pSha, hv.m_pVal, 1);
	secp256k1_sha256_write_Num(pSha, nType);
	secp256k1_sha256_write(pSha, hv.m_pVal, 1); // nested break
}

//////////////////////////////
// KeyKeeper - pub Kdf export
__stack_hungry__
static void Kdf2Pub(const Kdf* pKdf, KdfPub* pRes)
{
	Context* pCtx = Context_get();

	pRes->m_Secret = pKdf->m_Secret;

	secp256k1_gej gej;
	secp256k1_ge ge;

	MulPoint(&gej, pCtx->m_pGenGJ, &pKdf->m_kCoFactor);
	Point_Ge_from_Gej(&ge, &gej);
	Point_Compact_from_Ge(&pRes->m_CoFactorG, &ge);

	MulPoint(&gej, pCtx->m_pGenGJ + 1, &pKdf->m_kCoFactor);
	Point_Ge_from_Gej(&ge, &gej);
	Point_Compact_from_Ge(&pRes->m_CoFactorJ, &ge);
}

__stack_hungry__
void KeyKeeper_GetPKdf(const KeyKeeper* p, KdfPub* pRes, const uint32_t* pChild)
{
	if (pChild)
	{
		Kdf kdfChild;
		Kdf_getChild(&kdfChild, *pChild, &p->m_MasterKey);
		Kdf2Pub(&kdfChild, pRes);
	}
	else
		Kdf2Pub(&p->m_MasterKey, pRes);
}



//////////////////
// Protocol
#define PROTO_METHOD(name) __stack_hungry__ static uint16_t HandleProto_##name(KeyKeeper* p, OpIn_##name* pIn, uint32_t nIn, OpOut_##name* pOut, uint32_t nOut, uint32_t* pOutSize)

#define PROTO_UNUSED_ARGS \
	UNUSED(p); \
	UNUSED(pIn); \
	UNUSED(nIn); \
	UNUSED(pOut); \
	UNUSED(nOut);  \
	UNUSED(pOutSize);

#pragma pack (push, 1)
#define THE_MACRO_Field(type, name) type m_##name;
#define THE_MACRO_OpCode(id, name) \
typedef struct { \
	uint8_t m_OpCode; \
	BeamCrypto_ProtoRequest_##name(THE_MACRO_Field) \
} OpIn_##name; \
typedef struct { \
	uint8_t m_StatusCode; \
	BeamCrypto_ProtoResponse_##name(THE_MACRO_Field) \
} OpOut_##name; \
PROTO_METHOD(name);

BeamCrypto_ProtoMethods(THE_MACRO_OpCode)

#undef THE_MACRO_OpCode
#undef THE_MACRO_Field

#pragma pack (pop)

__attribute__((noinline))
void memcpy_unaligned(void* pDst, const void* pSrc, uint32_t n)
{
	memcpy(pDst, pSrc, n);
}

#define H2N_uint(n_val_unaligned, h_val, bits) \
do { \
	uint##bits##_t n_val = bswap##bits##_le(h_val); \
	static_assert(sizeof(n_val_unaligned) == sizeof(n_val), ""); \
	memcpy_unaligned(&n_val_unaligned, &n_val, sizeof(n_val)); \
} while(0)

#define N2H_uint_inplace(val, bits) \
do { \
	static_assert(sizeof(val) == sizeof(uint##bits##_t), ""); \
	val = bswap##bits##_le(val); \
} while(0)

#define N2H_uint(h_val, n_val_unaligned, bits) \
do { \
	static_assert(sizeof(n_val_unaligned) == sizeof(h_val), ""); \
	memcpy_unaligned(&h_val, &n_val_unaligned, sizeof(h_val)); \
	N2H_uint_inplace(h_val, bits); \
} while(0)

void N2H_CoinID(CoinID* p, const CoinID* p_unaligned)
{
	memcpy_unaligned(p, p_unaligned, sizeof(*p));

	N2H_uint_inplace(p->m_Amount, 64);
	N2H_uint_inplace(p->m_Idx, 64);
	N2H_uint_inplace(p->m_AssetID, 32);
	N2H_uint_inplace(p->m_SubIdx, 32);
	N2H_uint_inplace(p->m_Type, 32);
}

void N2H_ShieldedInput_Fmt(ShieldedInput_Fmt* p, const ShieldedInput_Fmt* p_unaligned)
{
	memcpy_unaligned(p, p_unaligned, sizeof(*p));

	N2H_uint_inplace(p->m_Fee, 64);
	N2H_uint_inplace(p->m_Amount, 64);
	N2H_uint_inplace(p->m_AssetID, 32);
	N2H_uint_inplace(p->m_nViewerIdx, 32);
}

void N2H_TxCommonIn(TxCommonIn* p, const TxCommonIn* p_unaligned)
{
	memcpy_unaligned(p, p_unaligned, sizeof(*p));

	N2H_uint_inplace(p->m_Krn.m_Fee, 64);
	N2H_uint_inplace(p->m_Krn.m_hMin, 64);
	N2H_uint_inplace(p->m_Krn.m_hMax, 64);
}

uint16_t MakeStatus(uint8_t major, uint8_t minor)
{
	return (((uint16_t) minor) << 8) | major;
}

uint16_t KeyKeeper_Invoke(KeyKeeper* p, uint8_t* pIn, uint32_t nIn, uint8_t* pOut, uint32_t* pOutSize)
{
	if (!nIn)
		return MakeStatus(c_KeyKeeper_Status_ProtoError, 0xfd);

	uint32_t nOutSize = *pOutSize;

	switch (*pIn)
	{
#define THE_MACRO(id, name) \
	case id: \
	{ \
		if ((nIn < sizeof(OpIn_##name)) || (nOutSize < sizeof(OpOut_##name))) \
			return MakeStatus(c_KeyKeeper_Status_ProtoError, 0xfe); \
 \
		*pOutSize = sizeof(OpOut_##name); \
\
		return HandleProto_##name(p, (OpIn_##name*) pIn, nIn - sizeof(OpIn_##name), (OpOut_##name*) pOut, nOutSize - sizeof(OpOut_##name), pOutSize); \
 	} \
	break; \

		BeamCrypto_ProtoMethods(THE_MACRO)
#undef THE_MACRO

	}

	return MakeStatus(c_KeyKeeper_Status_ProtoError, 0xff);
}

PROTO_METHOD(Version)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	static_assert(sizeof(pOut->m_Signature) == sizeof(BeamCrypto_CurrentSignature) - sizeof(char), "");
	memcpy(pOut->m_Signature, BeamCrypto_CurrentSignature, sizeof(BeamCrypto_CurrentSignature) - sizeof(char));

	return c_KeyKeeper_Status_Ok;
}

PROTO_METHOD(GetNumSlots)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	H2N_uint(pOut->m_Value, KeyKeeper_getNumSlots(p), 32);


	return c_KeyKeeper_Status_Ok;
}

PROTO_METHOD(GetPKdf)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	uint32_t iChild = (uint32_t) -1;
	KeyKeeper_GetPKdf(p, &pOut->m_Value, pIn->m_Kind ? &iChild : 0);

	return c_KeyKeeper_Status_Ok;
}

PROTO_METHOD(GetImage)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	uint32_t iChild;
	N2H_uint(iChild, pIn->m_iChild, 32);

	Kdf kdfC;
	Kdf_getChild(&kdfC, iChild, &p->m_MasterKey);

	secp256k1_scalar sk;
	Kdf_Derive_SKey(&kdfC, &pIn->m_hvSrc, &sk);
	SECURE_ERASE_OBJ(kdfC);

	const uint8_t pFlag[] = {
		pIn->m_bG, // copy, coz it'd be overwritten by the result
		pIn->m_bJ
	};
	secp256k1_gej pGej[_countof(pFlag)];

	unsigned int nCount = 0;

	for (unsigned int i = 0; i < _countof(pGej); i++)
	{
		if (!pFlag[i])
			continue;

		MulPoint(pGej + i, Context_get()->m_pGenGJ + i, &sk);
		nCount++;
	}

	if (!nCount)
		return c_KeyKeeper_Status_Unspecified;

	if (_countof(pGej) == nCount)
		Point_Gej_2_Normalize(pGej);

	CompactPoint* pRes = &pOut->m_ptImageG;

	for (unsigned int i = 0; i < _countof(pGej); i++)
	{
		if (_countof(pGej) == nCount)
			Point_Compact_from_Ge(pRes + i, (secp256k1_ge*) (pGej + i));
		else
		{
			if (pFlag[i])
			{
				secp256k1_ge ge;
				Point_Ge_from_Gej(&ge, pGej + i);
				Point_Compact_from_Ge(pRes + i, &ge);
			}
			else
				ZERO_OBJ(pRes[i]);
		}
	}

	return c_KeyKeeper_Status_Ok;
}

PROTO_METHOD(CreateOutput)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	RangeProof ctx;
	N2H_CoinID(&ctx.m_Cid, &pIn->m_Cid);
	ctx.m_pKdf = &p->m_MasterKey;
	ctx.m_pT_In = pIn->m_pT;
	ctx.m_pT_Out = pIn->m_pT; // use same buf (since we changed to in/out buf design). Copy res later

	secp256k1_scalar sBuf;
	ctx.m_pTauX = &sBuf;

	static_assert(sizeof(UintBig) == sizeof(secp256k1_scalar), "");

	if (memis0(pIn->m_pKExtra->m_pVal, sizeof(pIn->m_pKExtra)))
		ctx.m_pKExtra = 0;
	else
		ctx.m_pKExtra = pIn->m_pKExtra;

	ctx.m_pAssetGen = IsUintBigZero(&pIn->m_ptAssetGen.m_X) ? 0 : &pIn->m_ptAssetGen;

	if (!RangeProof_Calculate(&ctx))
		return c_KeyKeeper_Status_Unspecified;

	// copy into out. Do it carefully, since in/out share the same mem
	static_assert(sizeof(pOut->m_pT) == sizeof(pIn->m_pT), "");
	memmove(pOut->m_pT, pIn->m_pT, sizeof(pOut->m_pT)); // MUST use memmove!

	secp256k1_scalar_get_b32(pOut->m_TauX.m_pVal, &sBuf);

	return c_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - transaction common. Aggregation
static int TxAggr_AddAmount_Raw(int64_t* pRcv, Amount newVal, int isOut)
{
	// beware of overflow
	int64_t val0 = *pRcv;

	if (isOut)
	{
		*pRcv += newVal;
		if (*pRcv < val0)
			return 0;
	}
	else
	{
		*pRcv -= newVal;
		if (*pRcv > val0)
			return 0;
	}

	return 1;
}
static int TxAggr_AddAmount(KeyKeeper* p, Amount newVal, AssetID aid, int isOut)
{
	int64_t* pRcv = &p->u.m_TxBalance.m_RcvBeam;

	if (aid)
	{
		if (p->u.m_TxBalance.m_Aid)
		{
			if (p->u.m_TxBalance.m_Aid != aid)
				return 0; // only 1 additional asset type is supported in a tx
		}
		else
			p->u.m_TxBalance.m_Aid = aid;

		pRcv = &p->u.m_TxBalance.m_RcvAsset;
	}

	return TxAggr_AddAmount_Raw(pRcv, newVal, isOut);
}

__stack_hungry__
static uint16_t TxAggr_AddCoins(KeyKeeper* p, CoinID* pCid_unaligned, uint32_t nCount, int isOut)
{
	for (uint32_t i = 0; i < nCount; i++)
	{
		CoinID cid;
		N2H_CoinID(&cid, pCid_unaligned + i);

		uint8_t nScheme;
		uint32_t nSubkey;
		CoinID_getSchemeAndSubkey(&cid, &nScheme, &nSubkey);

		if (nSubkey && isOut)
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 3); // HW wallet should not send funds to child subkeys (potentially belonging to miners)

		switch (nScheme)
		{
		case c_CoinID_Scheme_V0:
		case c_CoinID_Scheme_BB21:
			// weak schemes
			if (isOut)
				return MakeStatus(c_KeyKeeper_Status_Unspecified, 4); // no reason to create weak outputs

			if (!KeyKeeper_AllowWeakInputs(p))
				return MakeStatus(c_KeyKeeper_Status_Unspecified, 5);
		}

		if (!TxAggr_AddAmount(p, cid.m_Amount, cid.m_AssetID, isOut))
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 1);

		secp256k1_scalar sk;
		CoinID_getSk(&p->m_MasterKey, &cid, &sk);

		if (!isOut)
			secp256k1_scalar_negate(&sk, &sk);

		secp256k1_scalar_add(&p->u.m_TxBalance.m_sk, &p->u.m_TxBalance.m_sk, &sk);
		SECURE_ERASE_OBJ(sk);
	}

	return c_KeyKeeper_Status_Ok;
}

__stack_hungry__
static uint16_t TxAggr_AddShieldedInputs(KeyKeeper* p, uint8_t* pIns_unaligned, uint32_t nCount)
{
	for (uint32_t i = 0; i < nCount; i++)
	{
		const ShieldedInput_Blob* pBlob = (const ShieldedInput_Blob*) pIns_unaligned;
		pIns_unaligned += sizeof(ShieldedInput_Blob);

		ShieldedInput_Fmt fmt;
		N2H_ShieldedInput_Fmt(&fmt, (const ShieldedInput_Fmt*) pIns_unaligned);
		pIns_unaligned += sizeof(ShieldedInput_Fmt);

		if (!TxAggr_AddAmount(p, fmt.m_Amount, fmt.m_AssetID, 0))
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 1);

		if (fmt.m_Fee)
		{
			// Starding from HF3 shielded input fees are optional. And basically should not be used. But currently we support them
			if (fmt.m_Fee > KeyKeeper_get_MaxShieldedFee(p))
				return MakeStatus(c_KeyKeeper_Status_Unspecified, 8);

			p->u.m_TxBalance.m_ImplicitFee += fmt.m_Fee;
			if (p->u.m_TxBalance.m_ImplicitFee < fmt.m_Fee)
				return MakeStatus(c_KeyKeeper_Status_Unspecified, 1); // overflow

			if (!TxAggr_AddAmount(p, fmt.m_Fee, 0, 1))
				return MakeStatus(c_KeyKeeper_Status_Unspecified, 1);
		}

		secp256k1_scalar sk;
		ShieldedInput_getSk(p, pBlob, &fmt, &sk);

		secp256k1_scalar_negate(&sk, &sk);
		secp256k1_scalar_add(&p->u.m_TxBalance.m_sk, &p->u.m_TxBalance.m_sk, &sk);
		SECURE_ERASE_OBJ(sk);
	}

	return c_KeyKeeper_Status_Ok;
}


static uint16_t TxAggr_AddAllCoins(KeyKeeper* p, const OpIn_TxAddCoins* pArg, uint32_t nSizeIn)
{
	uint32_t nSize =
		(sizeof(CoinID) * pArg->m_Ins) +
		(sizeof(CoinID) * pArg->m_Outs) +
		((sizeof(ShieldedInput_Blob) + sizeof(ShieldedInput_Fmt)) * pArg->m_InsShielded);

	if (nSizeIn != nSize)
		return c_KeyKeeper_Status_ProtoError;

	CoinID* pCid_unaligned = (CoinID*) (pArg + 1);

	uint16_t errCode = TxAggr_AddCoins(p, pCid_unaligned, pArg->m_Ins, 0);
	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	pCid_unaligned += pArg->m_Ins;

	errCode = TxAggr_AddCoins(p, pCid_unaligned, pArg->m_Outs, 1);
	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	pCid_unaligned += pArg->m_Outs;

	return TxAggr_AddShieldedInputs(p, (uint8_t*) pCid_unaligned, pArg->m_InsShielded);
}

static uint16_t TxAggr_Get(const KeyKeeper* p, Amount* pNetAmount, AssetID* pAid, const Amount* pFeeSender)
{
	if (c_KeyKeeper_State_TxBalance != p->m_State)
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 10);

	int64_t rcvVal = p->u.m_TxBalance.m_RcvBeam;
	if (pFeeSender)
	{
		// we're paying the fee. Subtract it from the net value we're sending
		if (!TxAggr_AddAmount_Raw(&rcvVal, *pFeeSender, 1))
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 1);
	}

	if (p->u.m_TxBalance.m_RcvAsset)
	{
		if (rcvVal)
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 11); // nnz net result in both beams and assets.

		rcvVal = p->u.m_TxBalance.m_RcvAsset;
		*pAid = p->u.m_TxBalance.m_Aid;
	}
	else
		*pAid = 0;

	if (pFeeSender)
	{
		if (rcvVal > 0)
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 12); // actually receiving

		*pNetAmount = -rcvVal;
	}
	else
	{
		if (rcvVal <= 0)
			return MakeStatus(c_KeyKeeper_Status_Unspecified, 13); // not receiving
		*pNetAmount = rcvVal;
	}

	return c_KeyKeeper_Status_Ok;
}

static void TxAggr_ToOffsetEx(const KeyKeeper* p, const secp256k1_scalar* pKrn, UintBig* pOffs)
{
	secp256k1_scalar kOffs;
	secp256k1_scalar_add(&kOffs, &p->u.m_TxBalance.m_sk, pKrn);
	secp256k1_scalar_negate(&kOffs, &kOffs);

	secp256k1_scalar_get_b32(pOffs->m_pVal, &kOffs);
	// kOffs isn't secret
}

static void TxAggr_ToOffset(const KeyKeeper* p, const secp256k1_scalar* pKrn, TxCommonOut* pTx)
{
	TxAggr_ToOffsetEx(p, pKrn, &pTx->m_TxSig.m_kOffset);
}

PROTO_METHOD(TxAddCoins)
{
	PROTO_UNUSED_ARGS;

	if ((pIn->m_Reset) || (c_KeyKeeper_State_TxBalance != p->m_State))
	{
		ZERO_OBJ(p->u);
		p->m_State = c_KeyKeeper_State_TxBalance;
	}

	uint16_t errCode = TxAggr_AddAllCoins(p, pIn, nIn);

	if (c_KeyKeeper_Status_Ok != errCode)
	{
		SECURE_ERASE_OBJ(p->u);
		p->m_State = 0;
	}

	return errCode;
}

//////////////////////////////
// KeyKeeper - Kernel modification
typedef struct
{
	secp256k1_scalar m_kKrn;
	secp256k1_scalar m_kNonce;
} KernelKeys;

__stack_hungry__
static int KernelUpdateKeysEx(TxKernelCommitments* pComms, const KernelKeys* pKeys, const TxKernelCommitments* pAdd)
{
	secp256k1_gej pGej[2];

	MulG(pGej, &pKeys->m_kKrn);
	MulG(pGej + 1, &pKeys->m_kNonce);

	if (pAdd)
	{
		secp256k1_ge ge;
		if (!Point_Ge_from_Compact(&ge, &pAdd->m_Commitment))
			return 0;

		wrap_gej_add_ge_var(pGej, pGej, &ge);

		if (!Point_Ge_from_Compact(&ge, &pAdd->m_NoncePub))
			return 0;

		wrap_gej_add_ge_var(pGej + 1, pGej + 1, &ge);
	}

	Point_Gej_2_Normalize(pGej);

	Point_Compact_from_Ge(&pComms->m_Commitment, (secp256k1_ge*) pGej);
	Point_Compact_from_Ge(&pComms->m_NoncePub, (secp256k1_ge*) (pGej + 1));

	return 1;
}

static int KernelUpdateKeys(TxKernelCommitments* pComms, const KernelKeys* pKeys, const TxKernelCommitments* pAdd)
{
	return KernelUpdateKeysEx(pComms, pKeys, pAdd);
}

__stack_hungry__
static void Kernel_SignPartial(UintBig* pSig, const TxKernelCommitments* pComms, const UintBig* pMsg, const KernelKeys* pKeys)
{
	// Note: 1st 2 arguments are unaligned
	secp256k1_scalar e;
	Signature_GetChallengeEx(&pComms->m_NoncePub, pMsg, &e);

	Signature_SignPartialEx(pSig, (secp256k1_scalar*) &e, &pKeys->m_kKrn, &pKeys->m_kNonce);
}


//////////////////////////////
// KeyKeeper - SplitTx
PROTO_METHOD(TxSplit)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	TxCommonIn txc;
	N2H_TxCommonIn(&txc, &pIn->m_Tx);

	Amount netAmount;
	AssetID aid;
	uint16_t errCode = TxAggr_Get(p, &netAmount, &aid, &txc.m_Krn.m_Fee);
	if (errCode)
		return errCode;

	if (netAmount)
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 21); // not split

	// hash all visible params
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_hMin);
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_hMax);
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_Fee);

	UintBig hv;
	secp256k1_scalar_get_b32(hv.m_pVal, &p->u.m_TxBalance.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	// derive keys
	static const char szSalt[] = "hw-wlt-split";
	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);

	KernelKeys keys;
	NonceGenerator_NextScalar(&ng, &keys.m_kKrn);
	NonceGenerator_NextScalar(&ng, &keys.m_kNonce);
	SECURE_ERASE_OBJ(ng);

	KernelUpdateKeys(&pOut->m_Tx.m_Comms, &keys, 0);

	TxKernel_getID(&txc.m_Krn, &pOut->m_Tx.m_Comms, &hv);

	errCode = KeyKeeper_ConfirmSpend(p, 0, 0, 0, &txc.m_Krn, &hv);
	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	Kernel_SignPartial(&pOut->m_Tx.m_TxSig.m_kSig, &pOut->m_Tx.m_Comms, &hv, &keys);

	TxAggr_ToOffset(p, &keys.m_kKrn, &pOut->m_Tx);

	SECURE_ERASE_OBJ(keys);

	return c_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - Receive + Send common stuff
__stack_hungry__
static void GetPaymentConfirmationMsg(UintBig* pRes, const UintBig* pSender, const UintBig* pKernelID, Amount amount, AssetID nAssetID)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	HASH_WRITE_STR(sha, "PaymentConfirmation");
	secp256k1_sha256_write(&sha, pKernelID->m_pVal, sizeof(pKernelID->m_pVal));
	secp256k1_sha256_write(&sha, pSender->m_pVal, sizeof(pSender->m_pVal));
	secp256k1_sha256_write_Num(&sha, amount);

	if (nAssetID)
	{
		HASH_WRITE_STR(sha, "asset");
		secp256k1_sha256_write_Num(&sha, nAssetID);
	}

	secp256k1_sha256_finalize(&sha, pRes->m_pVal);
}

__stack_hungry__
void DeriveAddress(const KeyKeeper* p, AddrID addrID, secp256k1_scalar* pKey, UintBig* pID)
{
	// derive key
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "kid");

	const uint32_t nType = FOURCC_FROM_STR(tRid);

	secp256k1_sha256_write_Num(&sha, addrID);
	secp256k1_sha256_write_Num(&sha, nType);
	secp256k1_sha256_write_Num(&sha, 0);
	secp256k1_sha256_finalize(&sha, pID->m_pVal);

	Kdf_Derive_SKey(&p->m_MasterKey, pID, pKey);
	Sk2Pk(pID, pKey);
}

//////////////////////////////
// KeyKeeper - ReceiveTx
PROTO_METHOD(TxReceive)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	Amount netAmount;
	AssetID aid;
	uint16_t errCode = TxAggr_Get(p, &netAmount, &aid, 0);
	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	assert(netAmount);

	TxCommonIn txc;
	N2H_TxCommonIn(&txc, &pIn->m_Tx);

	TxMutualIn txm;
	memcpy_unaligned(&txm, &pIn->m_Mut, sizeof(txm)); // save it before we generate output
	N2H_uint_inplace(txm.m_AddrID, 64);

	// Hash *ALL* the parameters, make the context unique
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	UintBig hv;
	TxKernel_getID(&txc.m_Krn, &pIn->m_Comms, &hv); // not a final ID yet

	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_write_CompactPoint(&sha, &pIn->m_Comms.m_NoncePub);

	uint8_t nFlag = 0; // not nonconventional
	secp256k1_sha256_write(&sha, &nFlag, sizeof(nFlag));
	secp256k1_sha256_write(&sha, pIn->m_Mut.m_Peer.m_pVal, sizeof(pIn->m_Mut.m_Peer.m_pVal));

	secp256k1_sha256_write_Num(&sha, txm.m_AddrID);

	secp256k1_scalar_get_b32(hv.m_pVal, &p->u.m_TxBalance.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));

	secp256k1_sha256_write_Num(&sha, netAmount); // the value being-received
	secp256k1_sha256_write_Num(&sha, aid);

	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	// derive keys
	static const char szSalt[] = "hw-wlt-rcv";
	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);

	KernelKeys keys;
	NonceGenerator_NextScalar(&ng, &keys.m_kKrn);
	NonceGenerator_NextScalar(&ng, &keys.m_kNonce);
	SECURE_ERASE_OBJ(ng);

	if (!KernelUpdateKeys(&pOut->m_Tx.m_Comms, &keys, &pIn->m_Comms)) // safe to call, even though pOut and pIn may overlap
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 22);

	TxKernel_getID(&txc.m_Krn, &pOut->m_Tx.m_Comms, &hv); // final ID
	Kernel_SignPartial(&pOut->m_Tx.m_TxSig.m_kSig, &pOut->m_Tx.m_Comms, &hv, &keys);

	TxAggr_ToOffset(p, &keys.m_kKrn, &pOut->m_Tx);

	if (txm.m_AddrID)
	{
		// sign
		UintBig hvID;
		DeriveAddress(p, txm.m_AddrID, &keys.m_kKrn, &hvID);
		GetPaymentConfirmationMsg(&hvID, &txm.m_Peer, &hv, netAmount, aid);
		Signature_Sign(&pOut->m_PaymentProof, &hvID, &keys.m_kKrn);
	}

	return c_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - DisplayAddress
PROTO_METHOD(DisplayAddress)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError; // size mismatch

	AddrID addrID;
	N2H_uint(addrID, pIn->m_AddrID, 64);

	secp256k1_scalar sk;
	UintBig hvAddr;

	DeriveAddress(p, addrID, &sk, &hvAddr);
	SECURE_ERASE_OBJ(sk);

	KeyKeeper_DisplayAddress(p, addrID, &hvAddr);

	return c_KeyKeeper_Status_Ok;
}


//////////////////////////////
// KeyKeeper - SendTx
typedef struct
{
	Amount m_netAmount;
	AssetID m_Aid;
	uint32_t m_iSlot;

	KernelKeys m_Keys;

	UintBig m_hvMyID;
	UintBig m_hvToken;

	TxCommonIn m_txc;

} TxSendContext;

__stack_hungry__
static void TxSend_DeriveKeys(KeyKeeper* p, const OpIn_TxSend2* pIn, TxSendContext* pCtx)
{
	AddrID addrID;
	N2H_uint(addrID, pIn->m_Mut.m_AddrID, 64);
	DeriveAddress(p, addrID, &pCtx->m_Keys.m_kNonce, &pCtx->m_hvMyID);

	KeyKeeper_ReadSlot(p, pCtx->m_iSlot, &pCtx->m_hvToken);
	Kdf_Derive_SKey(&p->m_MasterKey, &pCtx->m_hvToken, &pCtx->m_Keys.m_kNonce);

	// during negotiation kernel height and commitment are adjusted. We should only commit to the Fee
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write_Num(&sha, pCtx->m_txc.m_Krn.m_Fee);
	secp256k1_sha256_write(&sha, pIn->m_Mut.m_Peer.m_pVal, sizeof(pIn->m_Mut.m_Peer.m_pVal));
	secp256k1_sha256_write(&sha, pCtx->m_hvMyID.m_pVal, sizeof(pCtx->m_hvMyID.m_pVal));

	uint8_t nFlag = 0; // not nonconventional
	secp256k1_sha256_write(&sha, &nFlag, sizeof(nFlag));

	secp256k1_scalar_get_b32(pCtx->m_hvToken.m_pVal, &p->u.m_TxBalance.m_sk);
	secp256k1_sha256_write(&sha, pCtx->m_hvToken.m_pVal, sizeof(pCtx->m_hvToken.m_pVal));
	secp256k1_sha256_write_Num(&sha, pCtx->m_netAmount);
	secp256k1_sha256_write_Num(&sha, pCtx->m_Aid);

	secp256k1_scalar_get_b32(pCtx->m_hvToken.m_pVal, &pCtx->m_Keys.m_kNonce);
	secp256k1_sha256_write(&sha, pCtx->m_hvToken.m_pVal, sizeof(pCtx->m_hvToken.m_pVal));
	secp256k1_sha256_finalize(&sha, pCtx->m_hvToken.m_pVal);

	static const char szSalt[] = "hw-wlt-snd";
	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &pCtx->m_hvToken);
	NonceGenerator_NextScalar(&ng, &pCtx->m_Keys.m_kKrn);
	SECURE_ERASE_OBJ(ng);

	// derive tx token
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "tx.token");

	secp256k1_scalar_get_b32(pCtx->m_hvToken.m_pVal, &pCtx->m_Keys.m_kKrn);
	secp256k1_sha256_write(&sha, pCtx->m_hvToken.m_pVal, sizeof(pCtx->m_hvToken.m_pVal));
	secp256k1_sha256_finalize(&sha, pCtx->m_hvToken.m_pVal);

	if (IsUintBigZero(&pCtx->m_hvToken))
		pCtx->m_hvToken.m_pVal[_countof(pCtx->m_hvToken.m_pVal) - 1] = 1;
}

uint16_t HandleTxSend(KeyKeeper* p, OpIn_TxSend2* pIn, OpOut_TxSend1* pOut1, OpOut_TxSend2* pOut2)
{
	TxSendContext ctx;
	N2H_TxCommonIn(&ctx.m_txc, &pIn->m_Tx);

	uint16_t errCode = TxAggr_Get(p, &ctx.m_netAmount, &ctx.m_Aid, &ctx.m_txc.m_Krn.m_Fee);
	if (errCode)
		return errCode;

	if (!ctx.m_netAmount)
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 21); // not sending

	if (IsUintBigZero(&pIn->m_Mut.m_Peer))
		return MakeStatus(c_KeyKeeper_Status_UserAbort, 22); // conventional transfers must always be signed

	N2H_uint(ctx.m_iSlot, pIn->m_iSlot, 32);

	if (ctx.m_iSlot >= KeyKeeper_getNumSlots(p))
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 23);

	TxSend_DeriveKeys(p, pIn, &ctx);


	if (pOut1)
	{
		errCode = KeyKeeper_ConfirmSpend(p, ctx.m_netAmount, ctx.m_Aid, &pIn->m_Mut.m_Peer, &ctx.m_txc.m_Krn, 0);
		if (c_KeyKeeper_Status_Ok != errCode)
			return errCode;

		pOut1->m_UserAgreement = ctx.m_hvToken;

		KernelUpdateKeysEx(&pOut1->m_Comms, &ctx.m_Keys, 0);

		return c_KeyKeeper_Status_Ok;
	}

	assert(pOut2);

	if (memcmp(pIn->m_UserAgreement.m_pVal, ctx.m_hvToken.m_pVal, sizeof(ctx.m_hvToken.m_pVal)))
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 24); // incorrect user agreement token

	TxKernel_getID(&ctx.m_txc.m_Krn, &pIn->m_Comms, &ctx.m_hvToken);

	// verify payment confirmation signature
	GetPaymentConfirmationMsg(&ctx.m_hvMyID, &ctx.m_hvMyID, &ctx.m_hvToken, ctx.m_netAmount, ctx.m_Aid);

	if (!Signature_IsValid_Ex(&pIn->m_PaymentProof, &ctx.m_hvMyID, &pIn->m_Mut.m_Peer))
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 25);

	// 2nd user confirmation request. Now the kernel is complete, its ID is calculated
	errCode = KeyKeeper_ConfirmSpend(p, ctx.m_netAmount, ctx.m_Aid, &pIn->m_Mut.m_Peer, &ctx.m_txc.m_Krn, &ctx.m_hvMyID);
	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	// Regenerate the slot (BEFORE signing), and sign
	KeyKeeper_RegenerateSlot(p, ctx.m_iSlot);

	Kernel_SignPartial(&pOut2->m_TxSig.m_kSig, &pIn->m_Comms, &ctx.m_hvToken, &ctx.m_Keys); // safe to use pOut2 and pIn

	TxAggr_ToOffsetEx(p, &ctx.m_Keys.m_kKrn, &pOut2->m_TxSig.m_kOffset);

	return c_KeyKeeper_Status_Ok;
}

PROTO_METHOD(TxSend1)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	return HandleTxSend(p, (OpIn_TxSend2*) pIn, pOut, 0);
}

PROTO_METHOD(TxSend2)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	return HandleTxSend(p, pIn, 0, pOut);
}

//////////////////////////////
// Voucher
static void ShieldedHashTxt(secp256k1_sha256_t* pSha)
{
	secp256k1_sha256_initialize(pSha);
	HASH_WRITE_STR(*pSha, "Output.Shielded.");
}

typedef struct
{
	Kdf m_Gen;
	Kdf m_Ser;

} ShieldedViewer;

__stack_hungry__
static void ShieldedViewerInit(ShieldedViewer* pRes, uint32_t iViewer, const KeyKeeper* p)
{
	// Shielded viewer
	UintBig hv;
	secp256k1_sha256_t sha;
	secp256k1_scalar sk;

	ShieldedHashTxt(&sha);
	HASH_WRITE_STR(sha, "Own.Gen");
	secp256k1_sha256_write_Num(&sha, iViewer);
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	Kdf_Derive_PKey(&p->m_MasterKey, &hv, &sk);
	secp256k1_scalar_get_b32(hv.m_pVal, &sk);

	Kdf_Init(&pRes->m_Gen, &hv);

	ShieldedHashTxt(&sha);
	HASH_WRITE_STR(sha, "Own.Ser");
	secp256k1_sha256_write_Num(&sha, iViewer);
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	Kdf_Derive_PKey(&p->m_MasterKey, &hv, &sk);
	secp256k1_scalar_get_b32(hv.m_pVal, &sk);

	Kdf_Derive_PKey(&p->m_MasterKey, &hv, &sk);
	secp256k1_scalar_get_b32(hv.m_pVal, &sk);

	Kdf_Init(&pRes->m_Ser, &hv);
	secp256k1_scalar_mul(&pRes->m_Ser.m_kCoFactor, &pRes->m_Ser.m_kCoFactor, &sk);
}

static void MulGJ(secp256k1_gej* pGej, const secp256k1_scalar* pK)
{
	MultiMac_Context ctx;
	ctx.m_pRes = pGej;
	ctx.m_Fast.m_Count = 0;
	ctx.m_Secure.m_Count = 2;
	ctx.m_Secure.m_pGen = Context_get()->m_pGenGJ;
	ctx.m_Secure.m_pK = pK;

	MultiMac_Calculate(&ctx);
}

__stack_hungry__
static void Ticket_Hash(UintBig* pRes, const ShieldedVoucher* pVoucher)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "Out-S");
	secp256k1_sha256_write_CompactPoint(&sha, &pVoucher->m_SerialPub);
	secp256k1_sha256_finalize(&sha, pRes->m_pVal);
}

__stack_hungry__
static void Voucher_Hash(UintBig* pRes, const ShieldedVoucher* pVoucher)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "voucher.1");
	secp256k1_sha256_write_CompactPoint(&sha, &pVoucher->m_SerialPub);
	secp256k1_sha256_write_CompactPoint(&sha, &pVoucher->m_NoncePub);
	secp256k1_sha256_write(&sha, pVoucher->m_SharedSecret.m_pVal, sizeof(pVoucher->m_SharedSecret.m_pVal));
	secp256k1_sha256_finalize(&sha, pRes->m_pVal);
}

__stack_hungry__
static void ShieldedGetSpendKey(const ShieldedViewer* pViewer, const secp256k1_scalar* pkG, uint8_t nIsGenByViewer, UintBig* pPreimage, secp256k1_scalar* pSk)
{
	secp256k1_sha256_t sha;
	ShieldedHashTxt(&sha);
	HASH_WRITE_STR(sha, "kG-k");
	secp256k1_scalar_get_b32(pPreimage->m_pVal, pkG);
	secp256k1_sha256_write(&sha, pPreimage->m_pVal, sizeof(pPreimage->m_pVal));
	secp256k1_sha256_finalize(&sha, pPreimage->m_pVal);

	if (nIsGenByViewer)
		Kdf_Derive_SKey(&pViewer->m_Gen, pPreimage, pSk);
	else
		Kdf_Derive_PKey(&pViewer->m_Gen, pPreimage, pSk);

	ShieldedHashTxt(&sha);
	HASH_WRITE_STR(sha, "k-pI");
	secp256k1_scalar_get_b32(pPreimage->m_pVal, pSk);
	secp256k1_sha256_write(&sha, pPreimage->m_pVal, sizeof(pPreimage->m_pVal));
	secp256k1_sha256_finalize(&sha, pPreimage->m_pVal); // SerialPreimage

	Kdf_Derive_SKey(&pViewer->m_Ser, pPreimage, pSk); // spend sk
}

__stack_hungry__
static void CreateVoucherInternal(ShieldedVoucher* pRes, const UintBig* pNonce, const ShieldedViewer* pViewer)
{
	secp256k1_scalar pK[2], pN[2], sk;
	UintBig hv;
	Oracle oracle;

	// nonce -> kG
	ShieldedHashTxt(&oracle.m_sha);
	HASH_WRITE_STR(oracle.m_sha, "kG");
	secp256k1_sha256_write(&oracle.m_sha, pNonce->m_pVal, sizeof(pNonce->m_pVal));
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);
	Kdf_Derive_PKey(&pViewer->m_Gen, &hv, pK);

	// kG -> serial preimage and spend sk
	ShieldedGetSpendKey(pViewer, pK, 1, &hv, &sk);

	secp256k1_gej gej;
	MulG(&gej, &sk); // spend pk

	Oracle_Init(&oracle);
	HASH_WRITE_STR(oracle.m_sha, "L.Spend");

	secp256k1_sha256_write_Gej(&oracle.m_sha, &gej);
	Oracle_NextScalar(&oracle, pK + 1); // serial

	MulGJ(&gej, pK); // kG*G + serial*J
	Point_Compact_from_Gej(&pRes->m_SerialPub, &gej);

	// DH
	ShieldedHashTxt(&oracle.m_sha);
	HASH_WRITE_STR(oracle.m_sha, "DH");
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pRes->m_SerialPub);
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);
	Kdf_Derive_SKey(&pViewer->m_Gen, &hv, &sk); // DH multiplier

	secp256k1_scalar_mul(pN, pK, &sk);
	secp256k1_scalar_mul(pN + 1, pK + 1, &sk);
	MulGJ(&gej, pN); // shared point

	ShieldedHashTxt(&oracle.m_sha);
	HASH_WRITE_STR(oracle.m_sha, "sp-sec");
	secp256k1_sha256_write_Gej(&oracle.m_sha, &gej);
	secp256k1_sha256_finalize(&oracle.m_sha, pRes->m_SharedSecret.m_pVal); // Shared secret

	// nonces
	ShieldedHashTxt(&oracle.m_sha);
	HASH_WRITE_STR(oracle.m_sha, "nG");
	secp256k1_sha256_write(&oracle.m_sha, pRes->m_SharedSecret.m_pVal, sizeof(pRes->m_SharedSecret.m_pVal));
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);
	Kdf_Derive_PKey(&pViewer->m_Gen, &hv, pN);

	ShieldedHashTxt(&oracle.m_sha);
	HASH_WRITE_STR(oracle.m_sha, "nJ");
	secp256k1_sha256_write(&oracle.m_sha, pRes->m_SharedSecret.m_pVal, sizeof(pRes->m_SharedSecret.m_pVal));
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);
	Kdf_Derive_PKey(&pViewer->m_Gen, &hv, pN + 1);

	MulGJ(&gej, pN); // nG*G + nJ*J
	Point_Compact_from_Gej(&pRes->m_NoncePub, &gej);

	// sign it
	Ticket_Hash(&hv, pRes);
	Signature_GetChallengeEx(&pRes->m_NoncePub, &hv, &sk);
	Signature_SignPartialEx(pRes->m_pK, &sk, pK, pN);
	Signature_SignPartialEx(pRes->m_pK + 1, &sk, pK + 1, pN + 1);
}

PROTO_METHOD(CreateShieldedVouchers)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	AddrID addrID;
	N2H_uint(addrID, pIn->m_AddrID, 64);

	uint32_t nCount;
	N2H_uint(nCount, pIn->m_Count, 32);
	if (!nCount)
		return c_KeyKeeper_Status_Ok;

	uint32_t nSizeOut = sizeof(ShieldedVoucher) * nCount;
	if (nOut < nSizeOut)
		return MakeStatus(c_KeyKeeper_Status_ProtoError, 1);
	*pOutSize += nSizeOut;

	ShieldedViewer viewer;
	ShieldedViewerInit(&viewer, 0, p);

	// key to sign the voucher(s)
	UintBig hv, hvNonce;
	secp256k1_scalar skSign;
	DeriveAddress(p, addrID, &skSign, &hv);

	ShieldedVoucher* pRes = (ShieldedVoucher*)(pOut + 1); // no fields require alignment
	memcpy(&hvNonce, &pIn->m_Nonce0, sizeof(hvNonce));

	for (uint32_t i = 0; ; pRes++)
	{
		CreateVoucherInternal(pRes, &hvNonce, &viewer);

		Voucher_Hash(&hv, pRes);
		Signature_Sign(&pRes->m_Signature, &hv, &skSign);

		if (++i == nCount)
			break;

		// regenerate nonce
		Oracle oracle;
		secp256k1_sha256_initialize(&oracle.m_sha);
		HASH_WRITE_STR(oracle.m_sha, "sh.v.n");
		secp256k1_sha256_write(&oracle.m_sha, hvNonce.m_pVal, sizeof(hvNonce.m_pVal));
		secp256k1_sha256_finalize(&oracle.m_sha, hvNonce.m_pVal);
	}

	H2N_uint(pOut->m_Count, nCount, 32);

	return c_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - CreateShieldedInput
PROTO_METHOD(CreateShieldedInput)
{
	PROTO_UNUSED_ARGS;

	ShieldedInput_Fmt fmt;
	N2H_ShieldedInput_Fmt(&fmt, &pIn->m_InpFmt);

	CustomGenerator aGen;
	if (fmt.m_AssetID)
		CoinID_GenerateAGen(fmt.m_AssetID, &aGen);

	ShieldedInput_SpendParams sip;
	memcpy_unaligned(&sip, &pIn->m_SpendParams, sizeof(sip));
	N2H_uint_inplace(sip.m_hMin, 64);
	N2H_uint_inplace(sip.m_hMax, 64);
	N2H_uint_inplace(sip.m_WindowEnd, 64);
	N2H_uint_inplace(sip.m_Sigma_M, 32);
	N2H_uint_inplace(sip.m_Sigma_n, 32);

	CompactPoint* pG = (CompactPoint*)(pIn + 1);
	if (nIn != sizeof(*pG) * sip.m_Sigma_M)
		return c_KeyKeeper_Status_ProtoError;

	Oracle oracle;
	secp256k1_scalar skOutp, skSpend, pN[3];
	secp256k1_gej gej;
	UintBig hv, hvSigGen;

	ShieldedViewer viewer;
	ShieldedViewerInit(&viewer, fmt.m_nViewerIdx, p);

	// calculate kernel Msg
	TxKernel_SpecialMsg(&oracle.m_sha, fmt.m_Fee, sip.m_hMin, sip.m_hMax, 4);
	secp256k1_sha256_write_Num(&oracle.m_sha, sip.m_WindowEnd);
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);

	// init oracle
	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write(&oracle.m_sha, hv.m_pVal, sizeof(hv.m_pVal));

	// starting from HF3 commitmens to shielded state and asset are mandatory
	secp256k1_sha256_write(&oracle.m_sha, pIn->m_ShieldedState.m_pVal, sizeof(pIn->m_ShieldedState.m_pVal));
	secp256k1_sha256_write_CompactPointOptional2(&oracle.m_sha, &pIn->m_ptAssetGen, !IsUintBigZero(&pIn->m_ptAssetGen.m_X));

	secp256k1_sha256_write_Num(&oracle.m_sha, sip.m_Sigma_n);
	secp256k1_sha256_write_Num(&oracle.m_sha, sip.m_Sigma_M);

	// output commitment
	ShieldedInput_getSk(p, &pIn->m_InpBlob, &fmt, &skOutp); // TODO: use isolated child!
	CoinID_getCommRaw(&skOutp, fmt.m_Amount, fmt.m_AssetID ? &aGen : 0, &gej);
	secp256k1_sha256_write_Gej(&oracle.m_sha, &gej);

	// spend sk/pk
	int overflow;
	secp256k1_scalar_set_b32(&skSpend, pIn->m_InpBlob.m_kSerG.m_pVal, &overflow);
	if (overflow)
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 21);

	ShieldedGetSpendKey(&viewer, &skSpend, pIn->m_InpBlob.m_IsCreatedByViewer, &hv, &skSpend);
	MulG(&gej, &skSpend);
	secp256k1_sha256_write_Gej(&oracle.m_sha, &gej);

	Oracle_NextHash(&oracle, &hvSigGen);

	// Sigma::Part1
	for (uint32_t i = 0; i < _countof(pIn->m_pABCD); i++)
		secp256k1_sha256_write_CompactPoint(&oracle.m_sha, pIn->m_pABCD + i);

	{
		// hash all the visible to-date params
		union {
			secp256k1_sha256_t sha;
			NonceGenerator ng;
		} u;

		u.sha = oracle.m_sha; // copy
		for (uint32_t i = 0; i < sip.m_Sigma_M; i++)
			secp256k1_sha256_write_CompactPoint(&u.sha, pG + i);

		secp256k1_scalar_get_b32(hv.m_pVal, &skOutp); // secret (invisible for the host)
		secp256k1_sha256_write(&u.sha, hv.m_pVal, sizeof(hv.m_pVal));

		secp256k1_sha256_write(&u.sha, pIn->m_AssetSk.m_pVal, sizeof(pIn->m_AssetSk.m_pVal));
		secp256k1_sha256_write(&u.sha, pIn->m_OutpSk.m_pVal, sizeof(pIn->m_OutpSk.m_pVal));
		secp256k1_sha256_finalize(&u.sha, hv.m_pVal);

		// use current secret hv to seed our nonce generator
		static const char szSalt[] = "lelantus.1";
		NonceGenerator_Init(&u.ng, szSalt, sizeof(szSalt), &hv);

		for (uint32_t i = 0; i < _countof(pN); i++)
			NonceGenerator_NextScalar(&u.ng, pN + i);

		SECURE_ERASE_OBJ(u);
	}


	{
		// SigGen
		secp256k1_scalar sAmount, s1, e;

		s1 = pN[1]; // copy it, it'd be destroyed

		CoinID_getCommRawEx(pN, &s1, fmt.m_AssetID ? &aGen : 0, &gej);
		Point_Compact_from_Gej(&pOut->m_NoncePub, &gej);

		Oracle o2;
		Oracle_Init(&o2);
		secp256k1_sha256_write_CompactPoint(&o2.m_sha, &pOut->m_NoncePub);
		secp256k1_sha256_write(&o2.m_sha, hvSigGen.m_pVal, sizeof(hvSigGen.m_pVal));

		secp256k1_scalar_set_b32(&e, pIn->m_AssetSk.m_pVal, &overflow); // the 'mix' term

		// nG += nH * assetSk
		secp256k1_scalar_mul(&s1, &e, pN + 1);
		secp256k1_scalar_add(pN, pN, &s1);

		// skOutp` = skOutp + amount * assetSk
		secp256k1_scalar_set_u64(&sAmount, fmt.m_Amount);
		secp256k1_scalar_mul(&s1, &e, &sAmount);
		secp256k1_scalar_add(&s1, &s1, &skOutp);

		// 1st challenge
		Oracle_NextScalar(&o2, &e);

		secp256k1_scalar_mul(&s1, &s1, &e);
		secp256k1_scalar_add(pN, pN, &s1); // nG += skOutp` * e

		secp256k1_scalar_mul(&s1, &sAmount, &e);
		secp256k1_scalar_add(pN + 1, pN + 1, &s1); // nH += amount * e

		// 2nd challenge
		Oracle_NextScalar(&o2, &e);
		secp256k1_scalar_mul(&s1, &skSpend, &e);
		secp256k1_scalar_add(pN, pN, &s1); // nG += skSpend * e

		static_assert(_countof(pN) >= _countof(pOut->m_pSig), "");
		for (uint32_t i = 0; i < _countof(pOut->m_pSig); i++)
		{
			secp256k1_scalar_negate(pN + i, pN + i);
			secp256k1_scalar_get_b32(pOut->m_pSig[i].m_pVal, pN + i);
		}
	}

	secp256k1_ge ge;
	if (!Point_Ge_from_Compact(&ge, pG))
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 22); // import failed

	MulG(&gej, pN + 2);
	wrap_gej_add_ge_var(&gej, &gej, &ge);

	Point_Compact_from_Gej(&pOut->m_G0, &gej);
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pOut->m_G0);

	for (uint32_t i = 1; i < sip.m_Sigma_M; i++)
		secp256k1_sha256_write_CompactPoint(&oracle.m_sha, pG + i);

	secp256k1_scalar e, xPwr;
	Oracle_NextScalar(&oracle, &e);

	// calculate zR
	xPwr = e;
	for (uint32_t i = 1; i < sip.m_Sigma_M; i++)
		secp256k1_scalar_mul(&xPwr, &xPwr, &e);

	secp256k1_scalar_negate(&skOutp, &skOutp);
	secp256k1_scalar_set_b32(pN, pIn->m_OutpSk.m_pVal, &overflow);
	secp256k1_scalar_add(&skOutp, &skOutp, pN); // skOld - skNew
	secp256k1_scalar_mul(&skOutp, &skOutp, &xPwr);

	secp256k1_scalar_negate(pN + 2, pN + 2);
	secp256k1_scalar_add(pN + 2, pN + 2, &skOutp); // (skOld - skNew) * xPwr - tau

	secp256k1_scalar_get_b32(pOut->m_zR.m_pVal, pN + 2);


	SECURE_ERASE_OBJ(skSpend);
	SECURE_ERASE_OBJ(skOutp);
	SECURE_ERASE_OBJ(pN);

	return c_KeyKeeper_Status_Ok;
}


//////////////////////////////
// KeyKeeper - SendShieldedTx
static uint8_t Msg2Scalar(secp256k1_scalar* p, const UintBig* pMsg)
{
	int overflow;
	secp256k1_scalar_set_b32(p, pMsg->m_pVal, &overflow);
	return !!overflow;
}

__stack_hungry__
int VerifyShieldedOutputParams(const KeyKeeper* p, const OpIn_TxSendShielded* pSh, Amount amount, AssetID aid, const CustomGenerator* pAGen, secp256k1_scalar* pSk, UintBig* pKrnID, AddrID addrID)
{
	// check the voucher
	UintBig hv;
	Voucher_Hash(&hv, &pSh->m_Voucher);

	CompactPoint ptPubKey;
	ptPubKey.m_X = pSh->m_Mut.m_Peer;
	ptPubKey.m_Y = 0;

	if (!Signature_IsValid(&pSh->m_Voucher.m_Signature, &hv, &ptPubKey))
		return 0;
	// skip the voucher's ticket verification, don't care if it's valid, as it was already signed by the receiver.

	if (addrID)
	{
		DeriveAddress(p, addrID, pSk, &hv);
		if (memcmp(hv.m_pVal, pSh->m_Mut.m_Peer.m_pVal, sizeof(hv.m_pVal)))
			return 0;
	}

	// The host expects a TxKernelStd, which contains TxKernelShieldedOutput as a nested kernel, which contains the ShieldedTxo
	// This ShieldedTxo must use the ticket from the voucher, have appropriate commitment + rangeproof, which MUST be generated w.r.t. SharedSecret from the voucher.
	// The receiver *MUST* be able to decode all the parameters w.r.t. the protocol.
	//
	// So, here we ensure that the protocol is obeyed, i.e. the receiver will be able to decode all the parameters from the rangeproof
	//
	// Important: the TxKernelShieldedOutput kernel ID has the whole rangeproof serialized, means it can't be tampered with after we sign the outer kernel

	secp256k1_scalar pExtra[2];

	uint8_t nFlagsPacked = Msg2Scalar(pExtra, &pSh->m_User.m_Sender);

	{
		static const char szSalt[] = "kG-O";
		NonceGenerator ng; // not really secret
		NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &pSh->m_Voucher.m_SharedSecret);
		NonceGenerator_NextScalar(&ng, pSk);
	}

	secp256k1_scalar_add(pSk, pSk, pExtra); // output blinding factor

	secp256k1_gej gej;
	CoinID_getCommRaw(pSk, amount, pAGen, &gej); // output commitment

	nFlagsPacked |= (Msg2Scalar(pExtra, &pSh->m_User.m_pMessage[0]) << 1);
	nFlagsPacked |= (Msg2Scalar(pExtra + 1, &pSh->m_User.m_pMessage[1]) << 2);

	// We have the commitment, and params that are supposed to be packed in the rangeproof.
	// Recover the parameters, make sure they match

	Oracle oracle;
	TxKernel_SpecialMsg(&oracle.m_sha, 0, 0, -1, 3);
	secp256k1_sha256_finalize(&oracle.m_sha, pKrnID->m_pVal); // krn.Msg

	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write(&oracle.m_sha, pKrnID->m_pVal, sizeof(pKrnID->m_pVal)); // oracle << krn.Msg
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pSh->m_Voucher.m_SerialPub);
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pSh->m_Voucher.m_NoncePub);
	secp256k1_sha256_write_Gej(&oracle.m_sha, &gej);
	secp256k1_sha256_write_CompactPointOptional2(&oracle.m_sha, &pSh->m_ptAssetGen, !IsUintBigZero(&pSh->m_ptAssetGen.m_X)); // starting from HF3 it's mandatory

	{
		Oracle o2 = oracle;
		HASH_WRITE_STR(o2.m_sha, "bp-s");
		secp256k1_sha256_write(&o2.m_sha, pSh->m_Voucher.m_SharedSecret.m_pVal, sizeof(pSh->m_Voucher.m_SharedSecret.m_pVal));
		secp256k1_sha256_finalize(&o2.m_sha, hv.m_pVal); // seed
	}

	{
#pragma pack (push, 1)
		typedef struct
		{
			AssetID m_AssetID;
			uint8_t m_Flags;
		} ShieldedTxo_RangeProof_Packed;
#pragma pack (pop)

		secp256k1_scalar skRecovered;
		secp256k1_scalar pExtraRecovered[2];
		ShieldedTxo_RangeProof_Packed packed;

		RangeProof_Recovery_Context ctx;
		ctx.m_pExtra = 0;
		ctx.m_SeedGen = hv;
		ctx.m_pSeedSk = &ctx.m_SeedGen;
		ctx.m_pSk = &skRecovered;
		ctx.m_pUser = &packed;
		ctx.m_nUser = sizeof(packed);
		ctx.m_pExtra = pExtraRecovered;

		if (!RangeProof_Recover(&pSh->m_RangeProof, &oracle, &ctx))
			return 0;

		if (memcmp(pExtra, pExtraRecovered, sizeof(pExtra)) ||
			(packed.m_Flags != nFlagsPacked) ||
			(ctx.m_Amount != amount) ||
			(bswap32_be(packed.m_AssetID) != aid))
			return 0;

		if (aid || pSh->m_HideAssetAlways)
		{
			static const char szSalt[] = "skG-O";
			NonceGenerator ng; // not really secret
			NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &pSh->m_Voucher.m_SharedSecret);
			NonceGenerator_NextScalar(&ng, pExtraRecovered);

			secp256k1_scalar_set_u64(pExtraRecovered + 1, amount);
			secp256k1_scalar_mul(pExtraRecovered, pExtraRecovered, pExtraRecovered + 1);
			secp256k1_scalar_add(&skRecovered, &skRecovered, pExtraRecovered);
		}

		if (memcmp(pSk, &skRecovered, sizeof(skRecovered)))
			return 0;
	}

	// all match! Calculate the resulting kernelID
	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write(&oracle.m_sha, pKrnID->m_pVal, sizeof(pKrnID->m_pVal));
	secp256k1_sha256_write(&oracle.m_sha, (uint8_t*) &pSh->m_RangeProof, sizeof(pSh->m_RangeProof));
	secp256k1_sha256_finalize(&oracle.m_sha, pKrnID->m_pVal);

	return 1;
}

PROTO_METHOD(TxSendShielded)
{
	PROTO_UNUSED_ARGS;

	if (nIn)
		return c_KeyKeeper_Status_ProtoError;

	TxCommonIn txc;
	N2H_TxCommonIn(&txc, &pIn->m_Tx);

	AddrID addrID;
	N2H_uint(addrID, pIn->m_Mut.m_AddrID, 64);

	Amount netAmount;
	AssetID aid;
	uint16_t errCode = TxAggr_Get(p, &netAmount, &aid, &txc.m_Krn.m_Fee);
	if (errCode)
		return errCode;

	if (!netAmount)
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 21); // not sending

	if (IsUintBigZero(&pIn->m_Mut.m_Peer))
		return MakeStatus(c_KeyKeeper_Status_UserAbort, 22); // conventional transfers must always be signed

	CustomGenerator aGen;
	if (aid)
		CoinID_GenerateAGen(aid, &aGen);

	UintBig hvKrn1, hv;
	secp256k1_scalar skKrn1;
	if (!VerifyShieldedOutputParams(p, pIn, netAmount, aid, aid ? &aGen : 0, &skKrn1, &hvKrn1, addrID))
		return MakeStatus(c_KeyKeeper_Status_Unspecified, 23);

	// select blinding factor for the outer kernel.
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write(&sha, hvKrn1.m_pVal, sizeof(hvKrn1.m_pVal));
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_hMin);
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_hMax);
	secp256k1_sha256_write_Num(&sha, txc.m_Krn.m_Fee);
	secp256k1_scalar_get_b32(hv.m_pVal, &p->u.m_TxBalance.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	// derive keys
	KernelKeys keys;
	static const char szSalt[] = "hw-wlt-snd-sh";
	NonceGenerator ng;
	NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);
	NonceGenerator_NextScalar(&ng, &keys.m_kKrn);
	NonceGenerator_NextScalar(&ng, &keys.m_kNonce);
	SECURE_ERASE_OBJ(ng);

	KernelUpdateKeys(&pOut->m_Tx.m_Comms, &keys, 0);
	TxKernel_getID_Ex(&txc.m_Krn, &pOut->m_Tx.m_Comms, &hv, &hvKrn1, 1);

	// all set
	errCode = addrID ?
		KeyKeeper_ConfirmSpend(p, 0, 0, 0, &txc.m_Krn, &hv) :
		KeyKeeper_ConfirmSpend(p, netAmount, aid, &pIn->m_Mut.m_Peer, &txc.m_Krn, &hv);

	if (c_KeyKeeper_Status_Ok != errCode)
		return errCode;

	Kernel_SignPartial(&pOut->m_Tx.m_TxSig.m_kSig, &pOut->m_Tx.m_Comms, &hv, &keys);

	secp256k1_scalar_add(&keys.m_kKrn, &keys.m_kKrn, &skKrn1);
	TxAggr_ToOffset(p, &keys.m_kKrn, &pOut->m_Tx);

	return c_KeyKeeper_Status_Ok;
}
