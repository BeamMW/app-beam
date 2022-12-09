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

void KeyKeeper_ReadSlot(uint32_t iSlot, UintBig* pRes)
{
    UNUSED(iSlot);
    UNUSED(pRes);
}

void KeyKeeper_RegenerateSlot(uint32_t iSlot)
{
    UNUSED(iSlot);
}

int KeyKeeper_ConfirmSpend(Amount val, AssetID aid, const UintBig* pPeerID, const TxKernelUser* pUser, const TxKernelData* pData, const UintBig* pKrnID)
{
    UNUSED(val);
    UNUSED(aid);
    UNUSED(pPeerID);
    UNUSED(pUser);
    UNUSED(pData);
    UNUSED(pKrnID);

    return c_KeyKeeper_Status_Ok;
}



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
    } u;


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
    u.p4.rp.m_Cid.m_AssetID = 0;
    u.p4.rp.m_pKdf = &u.p4.kdf;
    u.p4.rp.m_pT_In = u.p4.pT;
    u.p4.rp.m_pT_Out = u.p4.pT;
    u.p4.rp.m_pTauX = &u.p4.tauX;

    StackMark();
    RangeProof_Calculate(&u.p4.rp);
    StackPrint(&u, "RangeProof_Calculate");

}

void app_main()
{

	_stack = STACK_MARK;
	
    StackTestFunc();

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
