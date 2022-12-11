/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include "os.h"
#include "ux.h"

#include "types.h"
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "handler/get_public_key.h"
#include "handler/sign_tx.h"

#include "hw_crypto/keykeeper.h"
#include "hw_crypto/multimac.h"
#include "hw_crypto/rangeproof.h"

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
global_ctx_t G_context;

void SecureEraseMem(void* p, uint32_t n)
{
	explicit_bzero(p, n);
}

uint32_t KeyKeeper_getNumSlots()
{
	return 32;
}

void KeyKeeper_ReadSlot(KeyKeeper* p, uint32_t iSlot, UintBig* pRes)
{
    UNUSED(p);
    UNUSED(iSlot);
    UNUSED(pRes);
}

void KeyKeeper_RegenerateSlot(KeyKeeper* p, uint32_t iSlot)
{
    UNUSED(p);
    UNUSED(iSlot);
}

Amount KeyKeeper_get_MaxShieldedFee()
{
    return 0;
}

int KeyKeeper_AllowWeakInputs(KeyKeeper* p)
{
    UNUSED(p);
    return 1;
}

int KeyKeeper_ConfirmSpend(KeyKeeper* p, Amount val, AssetID aid, const UintBig* pPeerID, const TxKernelUser* pUser, const UintBig* pKrnID)
{
    UNUSED(p);
    UNUSED(val);
    UNUSED(aid);
    UNUSED(pPeerID);
    UNUSED(pUser);
    UNUSED(pKrnID);

    return c_KeyKeeper_Status_Ok;
}

#pragma pack (push, 1)
#define THE_FIELD(type, name) type m_##name;

#define THE_MACRO(id, name) \
typedef struct { uint8_t m_OpCode; BeamCrypto_ProtoRequest_##name(THE_FIELD) } Proto_In_##name; \
typedef struct { BeamCrypto_ProtoResponse_##name(THE_FIELD) } Proto_Out_##name; \
const uint8_t g_Proto_Code_##name = id;

BeamCrypto_ProtoMethods(THE_MACRO)
#undef THE_MACRO
#undef THE_FIELD

#pragma pack (pop)


int OnApduRcv(unsigned int rcvLen)
{
    _Static_assert(sizeof(command_t) == 5, "");

    if (rcvLen < sizeof(command_t))
    {
        PRINTF("=> /!\\ too short\n");
/*
        {
            secp256k1_scalar tauX;
            memset(&tauX, 0, sizeof(tauX));

            Kdf kdf;
            Kdf_Init(&kdf, &tauX);

            CompactPoint pT[2];

            RangeProof rp;
            memset(&rp, 0, sizeof(rp));
            rp.m_Cid.m_Amount = 774440000;
            rp.m_Cid.m_SubIdx = 45;
            //rp.m_Cid.m_AssetID = 6;
            rp.m_pKdf = &kdf;
            rp.m_pT_In = pT;
            rp.m_pT_Out = pT;

            PRINTF("=> rp_ptr=%x\n", &rp);


            int res = RangeProof_Calculate(&rp);
            PRINTF("=> @ rp res=%d\n", res);
        }
*/

        return 0; // ignore
    }

    command_t* pCmd = (command_t*) G_io_apdu_buffer;
    if (rcvLen - sizeof(command_t) != pCmd->lc)
    {
        PRINTF("=> /!\\ Incorrect apdu LC: %.*H\n", rcvLen, G_io_apdu_buffer);

#ifdef DEBUG
        pCmd->lc = (uint8_r) (rcvLen - sizeof(command_t));
#else // DEBUG
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return 0; // ignore
#endif // DEBUG
    }

    PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
        pCmd->cla,
        pCmd->ins,
        pCmd->p1,
        pCmd->p2,
        pCmd->lc,
        pCmd->lc,
        pCmd->data);

    const uint8_t P2_LAST = 0x00; // Parameter 2 for last APDU to receive.
    const uint8_t P2_MORE = 0x80; // Parameter 2 for more APDU to receive.
    const uint8_t P1_START = 0x00; // Parameter 1 for first APDU number.
    const uint8_t P1_MAX = 0x03; // Parameter 1 for maximum APDU number.

    if (pCmd->cla != CLA)
        return io_send_sw(SW_CLA_NOT_SUPPORTED);

    buffer_t buf = { 0 };

    switch (pCmd->ins)
    {
    case GET_VERSION:

        if (pCmd->p1 != 0 || pCmd->p2 != 0)
            return io_send_sw(SW_WRONG_P1P2);

        _Static_assert(MAJOR_VERSION >= 0 && MAJOR_VERSION <= UINT8_MAX, "MAJOR version must be between 0 and 255!");
        _Static_assert(MINOR_VERSION >= 0 && MINOR_VERSION <= UINT8_MAX, "MINOR version must be between 0 and 255!");
        _Static_assert(PATCH_VERSION >= 0 && PATCH_VERSION <= UINT8_MAX, "PATCH version must be between 0 and 255!");

        static const uint8_t pRes[] = { MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION };
        _Static_assert(sizeof(pRes) == APPVERSION_LEN, "");

        return io_send_response(pRes, sizeof(pRes), SW_OK);

    case GET_APP_NAME:

        if (pCmd->p1 != 0 || pCmd->p2 != 0)
            return io_send_sw(SW_WRONG_P1P2);

        _Static_assert(APPNAME_LEN < MAX_APPNAME_LEN, "APPNAME must be at most 64 characters!");
        return io_send_response(APPNAME, APPNAME_LEN, SW_OK);

    case GET_PUBLIC_KEY:

        if (pCmd->p1 > 1 || pCmd->p2 > 0)
            return io_send_sw(SW_WRONG_P1P2);

        buf.ptr = pCmd->data;
        buf.size = pCmd->lc;
        buf.offset = 0;

        return handler_get_public_key(&buf, (bool)pCmd->p1);

    case SIGN_TX:

        if ((pCmd->p1 == P1_START && pCmd->p2 != P2_MORE) ||  //
            pCmd->p1 > P1_MAX ||                             //
            (pCmd->p2 != P2_LAST && pCmd->p2 != P2_MORE))
            return io_send_sw(SW_WRONG_P1P2);

        buf.ptr = pCmd->data;
        buf.size = pCmd->lc;
        buf.offset = 0;

        return handler_sign_tx(&buf, pCmd->p1, (bool)(pCmd->p2 & P2_MORE));
    }

    return io_send_sw(SW_INS_NOT_SUPPORTED);
}


/**
 * Handle APDU command received and send back APDU response using handlers.
 */

#define STACK_MARK 0xfadebabe

extern unsigned long _stack;

__attribute__((noinline))
void StackMark()
{
    uint32_t* pMark = (uint32_t*) &_stack;
    for (; ((uint32_t*) &pMark) - pMark > 20; pMark++)
        (*pMark) = STACK_MARK;
}

__attribute__((noinline))
void StackPrint(const void* p, const char* sz)
{
    uint32_t* pMark = (uint32_t*) &_stack;
    for (; ; pMark++)
        if ((*pMark) != STACK_MARK)
            break;

    PRINTF("@@ Op=%s, Stack consumed: %u\n", sz, (((uint32_t*) p) - pMark) * sizeof(uint32_t));
}

void StackTestFunc()
{
    union {

        struct {
            Kdf kdf1;
            Kdf kdf2;
            UintBig hv;
        } p1;

        struct {
            secp256k1_scalar s1, s2;
            MultiMac_WNaf wnaf;
            MultiMac_Context mmCtx;
            secp256k1_gej gej;
        } p2;

        struct {
            Kdf kdf;
            CoinID cid;
            secp256k1_scalar s;
            secp256k1_gej gej;

            struct {
                MultiMac_Fast_Custom aGen;
                secp256k1_fe zDenom;
            } aGen;

        } p3;


        struct {
            Kdf kdf;
            secp256k1_scalar tauX;
            CompactPoint pT[2];
            RangeProof rp;
        } p4;

        uint8_t m_pArr[4];
        uint32_t m_TheVal;

    } u;

    u.m_TheVal = 0;
    u.m_pArr[0] = 1;
    PRINTF("@@ TheVal = %u\n", u.m_TheVal);

    u.m_TheVal = __builtin_bswap32(u.m_TheVal);
    PRINTF("@@ TheVal = %u\n", u.m_TheVal);


    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &u) - ((uint8_t*) &_stack));
    PRINTF("@@ FastGen-custom size = %u\n", sizeof(u.p3.aGen));

    StackMark();

    memset(&u.p1.hv, 0, sizeof(u.p1.hv));
    Kdf_Init(&u.p1.kdf1, &u.p1.hv);

    StackPrint(&u, "Kdf_Init");
    StackMark();

    Kdf_getChild(&u.p1.kdf2, 14, &u.p1.kdf1);

    StackPrint(&u, "Kdf_getChild");
    StackMark();

    memset(&u.p2.s1, 0xa5, sizeof(u.p2.s1));
    memset(&u.p2.s2, 0x6c, sizeof(u.p2.s2));
    memset(&u.p2.mmCtx, 0, sizeof(u.p2.mmCtx));

    u.p2.mmCtx.m_pRes = &u.p2.gej;
    u.p2.mmCtx.m_Secure = 1;
    u.p2.mmCtx.m_pSecureK = &u.p2.s1;
    u.p2.mmCtx.m_pGenSecure = Context_get()->m_pGenGJ;
    u.p2.mmCtx.m_Fast = 1;
    u.p2.mmCtx.m_pFastK = &u.p2.s2;
    u.p2.mmCtx.m_pWnaf = &u.p2.wnaf;
    u.p2.mmCtx.m_FastGen.m_pPrecomputed = Context_get()->m_pGenFast + c_MultiMac_Fast_Idx_H;
    u.p2.mmCtx.m_pZDenom = 0;

    MultiMac_Calculate(&u.p2.mmCtx);

    StackPrint(&u, "MultiMac_Calculate");


    StackMark();
    void CoinID_GenerateAGen(AssetID aid, void* pAGen);
    CoinID_GenerateAGen(42, &u.p3.aGen);
    StackPrint(&u, "CoinID_GenerateAGen");


    Kdf_Init(&u.p3.kdf, &u.p1.hv); // don't care if p1.hv contains garbage

    memset(&u.p3.cid, 0, sizeof(u.p3.cid));
    u.p3.cid.m_Idx = 15;
    u.p3.cid.m_Type = 0x22;
    u.p3.cid.m_SubIdx = 8;
    u.p3.cid.m_Amount = 4500000000ull;
    u.p3.cid.m_AssetID = 0;

    StackMark();
    void CoinID_getCommRaw(const secp256k1_scalar* pK, Amount amount, const void* pAGen, secp256k1_gej* pGej);
    CoinID_getCommRaw(&u.p3.s, u.p3.cid.m_Amount, 0, &u.p3.gej);
    StackPrint(&u, "CoinID_getCommRaw without aid");

    StackMark();
    CoinID_getSk(&u.p3.kdf, &u.p3.cid, &u.p3.s);
    StackPrint(&u, "CoinID_getSk without aid");


    u.p3.cid.m_AssetID = 42;

    StackMark();
    CoinID_getCommRaw(&u.p3.s, u.p3.cid.m_Amount, &u.p3.aGen, &u.p3.gej);
    StackPrint(&u, "CoinID_getCommRaw with aid");

    StackMark();
    CoinID_getSk(&u.p3.kdf, &u.p3.cid, &u.p3.s);
    StackPrint(&u, "CoinID_getSk with aid");

    memset(&u.p4, 0, sizeof(u.p4));
    Kdf_Init(&u.p4.kdf, &u.p1.hv); // don't care if p1.hv contains garbage

    u.p4.rp.m_Cid.m_Amount = 774440000;
    u.p4.rp.m_Cid.m_SubIdx = 45;
    u.p4.rp.m_Cid.m_AssetID = 8;
    u.p4.rp.m_pKdf = &u.p4.kdf;
    u.p4.rp.m_pT_In = u.p4.pT;
    u.p4.rp.m_pT_Out = u.p4.pT;
    u.p4.rp.m_pTauX = &u.p4.tauX;

    StackMark();
    RangeProof_Calculate(&u.p4.rp);
    StackPrint(&u, "RangeProof_Calculate");

}

void GetWalletIDKey(const KeyKeeper* p, WalletIdentity nKey, secp256k1_scalar* pKey, UintBig* pID);

__attribute__((noinline))
void GetWalletIDKey2(const KeyKeeper* p, WalletIdentity nKey, UintBig* pID)
{
    secp256k1_scalar sk;
    GetWalletIDKey(p, nKey, &sk, pID);
}


void StackTestFunc2()
{
    struct
    {
        KeyKeeper kk1;
        KeyKeeper kk2;

        TxCommonOut m_TxAux;
        UintBig m_hvUserAggr;

        union
        {
            UintBig hv;
            secp256k1_scalar kTmp;

            union {
                Proto_In_GetNumSlots m_In;
                Proto_Out_GetNumSlots m_Out;
            } p1;

#pragma pack (push, 1)
            struct {

                Proto_In_TxAddCoins m_In;
                CoinID m_pCid[2];

            } p2;
#pragma pack (pop)

            union {
                Proto_In_TxSend1 m_In;
                Proto_Out_TxSend1 m_Out;
            } p3;

            union {
                Proto_In_TxReceive m_In;
                Proto_Out_TxReceive m_Out;
            } p4;

            union {
                Proto_In_TxSend2 m_In;
                Proto_Out_TxSend2 m_Out;
            } p5;

        } u;

    } s;

    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &s) - ((uint8_t*) &_stack));

    memset(&s.u.hv, 0, sizeof(s.u.hv));
    memset(&s.kk1, 0, sizeof(s.kk1));
    Kdf_Init(&s.kk1.m_MasterKey, &s.u.hv);

    s.u.hv.m_pVal[0] = 4;
    memset(&s.kk2, 0, sizeof(s.kk2));
    Kdf_Init(&s.kk2.m_MasterKey, &s.u.hv);

    StackMark();

    s.u.p1.m_In.m_OpCode = g_Proto_Code_GetNumSlots;
    int n = KeyKeeper_Invoke(&s.kk1, (uint8_t*) &s.u.p2, sizeof(s.u.p2.m_In), sizeof(Proto_Out_TxAddCoins));

    StackPrint(&s, "GetNumSlots");

    PRINTF("NumSlots = %u, ret=%d\n", s.u.p1.m_Out.m_Value, n);

    memset(&s.u.p2, 0, sizeof(s.u.p2));
    s.u.p2.m_In.m_OpCode = g_Proto_Code_TxAddCoins;
    s.u.p2.m_In.m_Reset = 1;
    s.u.p2.m_In.m_Ins = 2;
    s.u.p2.m_In.m_Outs = 0;
    s.u.p2.m_In.m_InsShielded = 0;
    s.u.p2.m_pCid[0].m_Idx = 1;
    s.u.p2.m_pCid[0].m_Amount = 100;
    s.u.p2.m_pCid[0].m_AssetID = 18;
    s.u.p2.m_pCid[0].m_SubIdx = 3u << 24;
    s.u.p2.m_pCid[1].m_Idx = 2;
    s.u.p2.m_pCid[1].m_Amount = 8;
    s.u.p2.m_pCid[1].m_SubIdx = 3u << 24;

    StackMark();
    n = KeyKeeper_Invoke(&s.kk1, (uint8_t*) &s.u.p2, sizeof(s.u.p2), sizeof(Proto_Out_TxAddCoins));
    StackPrint(&s, "kk1 TxAddCoins");

    memset(&s.u.p2, 0, sizeof(s.u.p2));
    s.u.p2.m_In.m_OpCode = g_Proto_Code_TxAddCoins;
    s.u.p2.m_In.m_Reset = 1;
    s.u.p2.m_In.m_Ins = 0;
    s.u.p2.m_In.m_Outs = 2;
    s.u.p2.m_In.m_InsShielded = 0;
    s.u.p2.m_pCid[0].m_Idx = 1;
    s.u.p2.m_pCid[0].m_Amount = 70;
    s.u.p2.m_pCid[0].m_AssetID = 18;
    s.u.p2.m_pCid[0].m_SubIdx = 3u << 24;
    s.u.p2.m_pCid[1].m_Idx = 2;
    s.u.p2.m_pCid[1].m_Amount = 30;
    s.u.p2.m_pCid[1].m_AssetID = 18;
    s.u.p2.m_pCid[1].m_SubIdx = 3u << 24;

    StackMark();
    n = KeyKeeper_Invoke(&s.kk2, (uint8_t*) &s.u.p2, sizeof(s.u.p2), sizeof(Proto_Out_TxAddCoins));
    StackPrint(&s, "kk2 TxAddCoins");

    PRINTF("ret=%d\n", n);
    PRINTF("kk1.state=%d, kk1.beams=%d" "\n", (int) s.kk1.m_State, (int) s.kk1.u.m_TxBalance.m_RcvBeam);
    PRINTF("kk2.state=%d, kk2.beams=%d" "\n", (int) s.kk2.m_State, (int) s.kk2.u.m_TxBalance.m_RcvBeam);
    //    PRINTF("** Kk sizes = %u, %u, %u\n", sizeof(s.kk), sizeof(s.kk.m_MasterKey), sizeof(s.kk.u));
    //PRINTF("** Kk =  %.*H\n", sizeof(s.kk1), &s.kk1);

    s.u.p3.m_In.m_OpCode = g_Proto_Code_TxSend1;
    s.u.p3.m_In.m_Tx.m_Krn.m_Fee = 8;
    s.u.p3.m_In.m_Tx.m_Krn.m_hMin = 100500;
    s.u.p3.m_In.m_Tx.m_Krn.m_hMax = 100600;
    GetWalletIDKey2(&s.kk2, 102, &s.u.p3.m_In.m_Mut.m_Peer);
    s.u.p3.m_In.m_Mut.m_MyIDKey = 101;
    s.u.p3.m_In.m_iSlot = 15;

    StackMark();
    n = KeyKeeper_Invoke(&s.kk1, (uint8_t*) &s.u.p3, sizeof(s.u.p3.m_In), sizeof(s.u.p3.m_Out));
    StackPrint(&s, "TxSend1");
    PRINTF("ret=%d\n", n);

    s.m_TxAux.m_Comms = s.u.p3.m_Out.m_Comms;
    s.m_hvUserAggr = s.u.p3.m_Out.m_UserAgreement;

    s.u.p4.m_In.m_OpCode = g_Proto_Code_TxReceive;
    s.u.p4.m_In.m_Tx.m_Krn.m_Fee = 8;
    s.u.p4.m_In.m_Tx.m_Krn.m_hMin = 100500;
    s.u.p4.m_In.m_Tx.m_Krn.m_hMax = 100600;
    GetWalletIDKey2(&s.kk1, 101, &s.u.p4.m_In.m_Mut.m_Peer);

   s.u.p4.m_In.m_Mut.m_MyIDKey = 102;
    s.u.p4.m_In.m_Comms = s.m_TxAux.m_Comms;

    StackMark();
    n = KeyKeeper_Invoke(&s.kk2, (uint8_t*) &s.u.p4, sizeof(s.u.p4.m_In), sizeof(s.u.p4.m_Out));
    StackPrint(&s, "TxReceive");
    PRINTF("ret=%d\n", n);

    memmove(&s.u.p5.m_In.m_PaymentProof, &s.u.p4.m_Out.m_PaymentProof, sizeof(s.u.p5.m_In.m_PaymentProof));

    s.m_TxAux = s.u.p4.m_Out.m_Tx;

    s.u.p5.m_In.m_OpCode = g_Proto_Code_TxSend2;
    s.u.p5.m_In.m_Tx.m_Krn.m_Fee = 8;
    s.u.p5.m_In.m_Tx.m_Krn.m_hMin = 100500;
    s.u.p5.m_In.m_Tx.m_Krn.m_hMax = 100600;
    GetWalletIDKey2(&s.kk2, 102, &s.u.p5.m_In.m_Mut.m_Peer);
    s.u.p5.m_In.m_Mut.m_MyIDKey = 101;
    s.u.p5.m_In.m_iSlot = 15;
    s.u.p5.m_In.m_Comms = s.m_TxAux.m_Comms;
    s.u.p5.m_In.m_UserAgreement = s.m_hvUserAggr;

    StackMark();
    n = KeyKeeper_Invoke(&s.kk1, (uint8_t*) &s.u.p5, sizeof(s.u.p5.m_In), sizeof(s.u.p5.m_Out));
    StackPrint(&s, "TxSend2");
    PRINTF("ret=%d\n", n);
}

void app_main()
{

	_stack = STACK_MARK;
	
    StackTestFunc();
    StackTestFunc2();

    io_init();

    // Reset context
    explicit_bzero(&G_context, sizeof(G_context));

    PRINTF("apdu_ptr=%x\n", G_io_apdu_buffer);
    PRINTF("apdu_len=%u\n", sizeof(G_io_apdu_buffer));
    PRINTF("uxbuf_len=%u\n", sizeof(G_io_seproxyhal_spi_buffer));
    PRINTF("gux_len=%u\n", sizeof(G_ux));
    PRINTF("gux_params_len=%u\n", sizeof(G_ux_params));
    PRINTF("G_context_len=%u\n", sizeof(G_context));
	PRINTF("canary_ptr=%x\n", &_stack);

	Context* pCtx = Context_get();
    PRINTF("ec_context_ptr=%x\n", pCtx);

    PRINTF("local_ptr=%x\n", &pCtx);

    for (;;) {

		PRINTF("Stack canary=%x\n", _stack);
		
        BEGIN_TRY{
            TRY {

                // Receive command bytes in G_io_apdu_buffer
                int inpLen = io_recv_command();
                if (inpLen < 0)
                {
                    CLOSE_TRY;
                    return;
                }

                PRINTF("=> Incoming command: %.*H\n", inpLen, G_io_apdu_buffer);

                // Dispatch structured APDU command to handler
                if (OnApduRcv(inpLen) < 0) {
                    CLOSE_TRY;
                    return;
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                io_send_sw(e);
            }
            FINALLY {
            }
            END_TRY;
        }
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/**
 * Main loop to setup USB, Bluetooth, UI and launch app_main().
 */
__attribute__((section(".boot"))) int main() {
    __asm volatile("cpsie i");

    os_boot();

    for (;;) {
        // Reset UI
        memset(&G_ux, 0, sizeof(G_ux));

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef TARGET_NANOX
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE
                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    app_exit();

    return 0;
}
