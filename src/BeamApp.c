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

#include "cx.h"
#include "BeamApp.h"
#include "sw.h"

#include "hw_crypto/keykeeper.h"
#include "hw_crypto/multimac.h"
#include "hw_crypto/rangeproof.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "secp256k1/src/hash_impl.h"
#pragma GCC diagnostic pop


#define c_Modal_Ok 1
#define c_Modal_Cancel 2

/////////////////////////////////////
// Formatting
#define c_LineMaxLen 20

char Hex2Char(uint8_t x)
{
    return (x >= 0xa) ? (x + ('a' - 0xa)) : (x + '0');
}

void PrintHex(char* sz, const uint8_t* p, unsigned int n)
{
    for (unsigned int i = 0; i < n; i++)
    {
        uint8_t x = p[i];
        *sz++ = Hex2Char(x >> 4);
        *sz++ = Hex2Char(x & 0xf);
    }
    *sz = 0;
}

void PrintUintBig(char* sz, const UintBig* p)
{
    PrintHex(sz, p->m_pVal, sizeof(UintBig));
}

void PrintUintBig_4(char* sz, const UintBig* p, uint32_t iStep)
{
    const uint8_t* pSrc = p->m_pVal + iStep * 8;

    for (unsigned int i = 0; ; )
    {
        PrintHex(sz, pSrc, 2);
        if (++i == 4)
            break;

        sz += 4;
        pSrc += 2;

        *sz++ = ' ';
    }
}

void PrintUintBig_8(char* sz, const UintBig* p, uint32_t iStep)
{
    const uint8_t* pSrc = p->m_pVal + iStep * 8;

    PrintHex(sz, pSrc, 4);
    sz[8] = ' ';
    sz[9] = '-';
    sz[10] = ' ';
    PrintHex(sz + 11, pSrc + 4, 4);
}

uint32_t Internal_Decimal_GetLen(uint32_t val)
{
    uint32_t len = 0;
    for (; val; val /= 10)
        len++;
    return len;
}

void Internal_PrintDecimal(char* sz, uint32_t val, uint32_t len)
{
    for (; len--; val /= 10)
        sz[len] = '0' + (val % 10);
}

uint32_t PrintDecimalAuto(char* sz, uint32_t val)
{
    uint32_t len = Internal_Decimal_GetLen(val);
    Internal_PrintDecimal(sz, val, len);
    sz[len] = 0;
    return len;
}

uint32_t Internal_PrintBeams(char* sz, Amount val)
{
    if (val >= 1000)
    {
        uint32_t len = Internal_PrintBeams(sz, val / 1000); // recursion

        sz[len++] = ',';
        Internal_PrintDecimal(sz + len, (uint32_t)(val % 1000), 3);
        return len + 3;
    }

    uint32_t len = (val >= 100) ? 3 : (val >= 10) ? 2 : 1;
    Internal_PrintDecimal(sz, (uint32_t) val, len);
    return len;
}

void PrintAmount(char* sz, Amount val)
{
    // amount format: 184,467,440,737.09551615
    uint32_t sep = 100000000u;

    // Can take up to 24 characetrs (though EXTREMELY unlikely), wherease we must fit 20 characters. In such a case the groths (after dot) would be truncated
    uint32_t len = Internal_PrintBeams(sz, val / sep);
    uint32_t groths = (uint32_t)(val % sep);
    assert(len < c_LineMaxLen);

    if (groths)
    {
        sz[len++] = '.';

        while (len < c_LineMaxLen)
        {
            sep /= 10;
            assert(sep && groths);

            sz[len++] = '0' + (uint8_t) (groths / sep);

            if (!(groths %= sep))
                break;
        }
    }

    sz[len] = 0;
}

void PrintAssetID(char* sz, AssetID aid)
{
    if (aid)
    {
        static const char s_szPrefix[] = "Aid-";
        memcpy(sz, s_szPrefix, sizeof(s_szPrefix) - 1);
        sz += sizeof(s_szPrefix) - 1;

        PrintDecimalAuto(sz, aid);
    }
    else
    {
        static const char s_szBeam[] = "BEAM";
        memcpy(sz, s_szBeam, sizeof(s_szBeam));
    }
}

/////////////////////////////////////
// State for ui elements on-demand formatting


static char g_szLine1[c_LineMaxLen + 1];
static char g_szLine2[c_LineMaxLen + 1];

union
{
    struct {
        AddrID m_addrID;
        const UintBig* m_pAddr;
    } m_Addr;

    struct {

        Amount m_Amount;
        Amount m_Fee;
        AssetID m_Aid;
        const UintBig* m_pAddr;
        //const TxKernelUser* m_pUser;
        uint32_t m_Flags;
        //const UintBig* m_pKrnID;

    } m_Spend;

    struct {
        uint32_t m_Number;
        uint8_t m_Step;
    } m_Account;

} g_Ux_U;

void PrintAddr_2Line(const UintBig* pAddr, uint32_t iStep)
{
    PrintUintBig_4(g_szLine1, pAddr, iStep);
    PrintUintBig_4(g_szLine2, pAddr, iStep + 1);
}

#ifdef TARGET_NANOSP
static char g_szLine3[c_LineMaxLen + 1];
static char g_szLine4[c_LineMaxLen + 1];

void PrintAddr_4Line(const UintBig* pAddr)
{
    PrintAddr_2Line(pAddr, 0);
    PrintUintBig_4(g_szLine3, pAddr, 2);
    PrintUintBig_4(g_szLine4, pAddr, 3);
}

#endif

void PrintTxType(char* sz)
{
    if (c_KeyKeeper_ConfirmSpend_Shielded & g_Ux_U.m_Spend.m_Flags)
    {
        static const char s_szType[] = "Lelantus-MW";
        memcpy(sz, s_szType, sizeof(s_szType));
    }
    else
    {
        static const char s_szType[] = "Mimble-Wimble";
        memcpy(sz, s_szType, sizeof(s_szType));
    }
}

KeyKeeper g_KeyKeeper;
KeyKeeper* KeyKeeper_Get()
{
    return &g_KeyKeeper;
}

#define c_KeyKeeper_Slots 16

volatile static const struct
{
    UintBig m_pSlot[c_KeyKeeper_Slots];

    uint32_t m_iAccount;

#ifdef BeamCrypto_ScarceStack
    KeyKeeper_AuxBuf m_AuxBuf; // goes to nvrom
#else // BeamCrypto_ScarceStack
#endif // BeamCrypto_ScarceStack


} N_Global __attribute__((aligned(64)));

bool InitMasterKey();

/////////////////////////////////////
// ui About
void ui_menu_main_about();

UX_STEP_NOCB(ux_step_about_info, bn, {"Beam App", "(c) 2020 Beam"});
UX_STEP_CB(ux_step_about_back, pb, ui_menu_main_about(), {&C_icon_back, "Back"});

UX_FLOW(
    ux_flow_about,
    &ux_step_about_info,
    &ux_step_about_back,
    FLOW_LOOP
);

void ui_menu_about()
{
    ux_flow_init(0, ux_flow_about, NULL);
}

/////////////////////////////////////
// ui Account
void PrintAccountNumber(char* sz, uint32_t iAccount)
{
    if (iAccount)
    {
        static const char s_szPrefix[] = "Account ";
        memcpy(sz, s_szPrefix, sizeof(s_szPrefix));

        PrintDecimalAuto(sz + sizeof(s_szPrefix) - 1, iAccount);
    }
    else
    {
        static const char s_szAccountDefault[] = "Default Account";
        memcpy(sz, s_szAccountDefault, sizeof(s_szAccountDefault));
    }
}

void OnAccountMove(uint8_t n)
{
    if (n != g_Ux_U.m_Account.m_Step)
    {
        uint8_t nDelta = (n + 3 - g_Ux_U.m_Account.m_Step) % 3;
        g_Ux_U.m_Account.m_Step = n;

        if (1 != nDelta)
            nDelta = 99;

        g_Ux_U.m_Account.m_Number = (g_Ux_U.m_Account.m_Number + nDelta) % 100;
        PRINTF("Account=%u\n", g_Ux_U.m_Account.m_Number);
    }

    PrintAccountNumber(g_szLine2, g_Ux_U.m_Account.m_Number);
}

UX_STEP_CB_INIT(ux_step_account_0, pnn, OnAccountMove(0), EndModal(c_Modal_Ok), { &C_beam_logo, "Choose account", g_szLine2 });
UX_STEP_CB_INIT(ux_step_account_1, pnn, OnAccountMove(1), EndModal(c_Modal_Ok), { &C_beam_logo, "Choose account", g_szLine2 });
UX_STEP_CB_INIT(ux_step_account_2, pnn, OnAccountMove(2), EndModal(c_Modal_Ok), { &C_beam_logo, "Choose account", g_szLine2 });

UX_FLOW(ux_flow_account,
    &ux_step_account_0,
    &ux_step_account_1,
    &ux_step_account_2,
    FLOW_LOOP);

void ui_menu_main_account();

void ui_menu_account()
{
    g_Ux_U.m_Account.m_Number = N_Global.m_iAccount;
    g_Ux_U.m_Account.m_Step = 0;

    ux_flow_init(0, ux_flow_account, 0);
    uint8_t res = DoModal();

    if (c_Modal_Ok == res)
    {
        nvm_write((void*) &N_Global.m_iAccount, &g_Ux_U.m_Account.m_Number, sizeof(g_Ux_U.m_Account.m_Number));
        InitMasterKey();
    }

    ui_menu_main_account();
}

/////////////////////////////////////
// ui Main
void OnMainAccount()
{
    UintBig hv;
    secp256k1_scalar sk;

    void DeriveAddress(const KeyKeeper* p, AddrID addrID, secp256k1_scalar * pKey, UintBig * pAddr);
    DeriveAddress(KeyKeeper_Get(), 0, &sk, &hv);
    SecureEraseMem(&sk, sizeof(sk));

    PrintAccountNumber(g_szLine1, N_Global.m_iAccount);

    PrintHex(g_szLine2, hv.m_pVal, 8);
}

UX_STEP_NOCB(ux_step_main_ready, pnn, { &C_beam_logo, "Beam", "is ready" }); 
UX_STEP_CB_INIT(ux_step_main_account, nn, OnMainAccount(), ui_menu_account(), { g_szLine1, g_szLine2 });
UX_STEP_NOCB(ux_step_main_version, bn, { "Version", APPVERSION });
UX_STEP_CB(ux_step_main_about, pb, ui_menu_about(), { &C_icon_certificate, "About" });
UX_STEP_VALID(ux_step_main_quit, pb, os_sched_exit(-1), { &C_icon_dashboard_x, "Quit" });

UX_FLOW(ux_flow_main,
    &ux_step_main_ready,
    &ux_step_main_account,
    &ux_step_main_version,
    &ux_step_main_about,
    &ux_step_main_quit,
    FLOW_LOOP);

void ui_menu_main()
{
    ux_flow_init(0, ux_flow_main, NULL);
}

void ui_menu_main_account()
{
    ux_flow_init(0, ux_flow_main, &ux_step_main_account);
}

void ui_menu_main_about()
{
    ux_flow_init(0, ux_flow_main, &ux_step_main_about);
}

//////////////////////
// Display address
UX_STEP_CB(ux_step_address_review, bb, EndModal(c_Modal_Ok), { "Please review", "Your address" });
#ifdef TARGET_NANOSP
UX_STEP_CB_INIT(ux_step_address_x, nnnn, PrintAddr_4Line(g_Ux_U.m_Addr.m_pAddr), EndModal(c_Modal_Cancel), { g_szLine1, g_szLine2, g_szLine3, g_szLine4 });
#else // TARGET_NANOSP
UX_STEP_CB_INIT(ux_step_address_1, nn, PrintAddr_2Line(g_Ux_U.m_Addr.m_pAddr, 0), EndModal(c_Modal_Cancel), { g_szLine1, g_szLine2 });
UX_STEP_CB_INIT(ux_step_address_2, nn, PrintAddr_2Line(g_Ux_U.m_Addr.m_pAddr, 2), EndModal(c_Modal_Cancel), { g_szLine1, g_szLine2 });
#endif // TARGET_NANOSP

UX_FLOW(ux_flow_address,
    &ux_step_address_review,
#ifdef TARGET_NANOSP
    & ux_step_address_x
#else // TARGET_NANOSP
    & ux_step_address_1,
    & ux_step_address_2
#endif // TARGET_NANOSP
);


void KeyKeeper_DisplayAddress(KeyKeeper* p, AddrID addrID, const UintBig* pAddr)
{
    UNUSED(p);

    g_Ux_U.m_Addr.m_addrID = addrID;
    g_Ux_U.m_Addr.m_pAddr = pAddr;

    ux_flow_init(0, ux_flow_address, NULL);
    DoModal();
    ui_menu_main();
}


//////////////////////
// Confirm Spend
UX_STEP_NOCB(ux_step_send_review, bb, { "Please review", "send transaction" });
#ifdef TARGET_NANOSP
UX_STEP_NOCB_INIT(ux_step_send_amount_asset, bnnn, (PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_Amount), PrintAssetID(g_szLine2, g_Ux_U.m_Spend.m_Aid)), { "Amount", g_szLine1, "Asset", g_szLine2 });
UX_STEP_NOCB_INIT(ux_step_send_fee_type, bnnn, (PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_Fee), PrintTxType(g_szLine2)), { "Fee", g_szLine1, "Type", g_szLine2 });
#else // TARGET_NANOSP
UX_STEP_NOCB_INIT(ux_step_send_amount, bn, PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_Amount), { "Amount", g_szLine1 });
UX_STEP_NOCB_INIT(ux_step_send_asset, bn, PrintAssetID(g_szLine1, g_Ux_U.m_Spend.m_Aid), { "Asset", g_szLine1 });
UX_STEP_NOCB_INIT(ux_step_send_fee, bn, PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_Fee), { "Fee", g_szLine1 });
UX_STEP_NOCB_INIT(ux_step_send_type, bn, PrintTxType(g_szLine1), { "Type", g_szLine1 });
#endif // TARGET_NANOSP
UX_STEP_NOCB(ux_step_send_receiver, pb, { &C_icon_certificate, "Receiver address" });
#ifdef TARGET_NANOSP
UX_STEP_NOCB_INIT(ux_step_send_receiver_x, nnnn, PrintAddr_4Line(g_Ux_U.m_Spend.m_pAddr), { g_szLine1, g_szLine2, g_szLine3, g_szLine4 });
#else // TARGET_NANOSP
UX_STEP_NOCB_INIT(ux_step_send_receiver_1, nn, PrintAddr_2Line(g_Ux_U.m_Spend.m_pAddr, 0), { g_szLine1, g_szLine2 });
UX_STEP_NOCB_INIT(ux_step_send_receiver_2, nn, PrintAddr_2Line(g_Ux_U.m_Spend.m_pAddr, 2), { g_szLine1, g_szLine2 });
#endif // TARGET_NANOSP
//UX_STEP_NOCB(ux_step_send_krnid, pb, { &C_icon_certificate, "Kernel ID" });
//#ifdef TARGET_NANOSP
//UX_STEP_NOCB_INIT(ux_step_send_krnid_x, nnnn, PrintAddr_4Line(g_Ux_U.m_Spend.m_pKrnID), { g_szLine1, g_szLine2, g_szLine3, g_szLine4 });
//#else // TARGET_NANOSP
//UX_STEP_NOCB_INIT(ux_step_send_krnid_1, nn, PrintAddr_2Line(g_Ux_U.m_Spend.m_pKrnID, 0), { g_szLine1, g_szLine2 });
//UX_STEP_NOCB_INIT(ux_step_send_krnid_2, nn, PrintAddr_2Line(g_Ux_U.m_Spend.m_pKrnID, 2), { g_szLine1, g_szLine2 });
//#endif // TARGET_NANOSP
UX_STEP_CB(ux_step_send_Ok, pb, EndModal(c_Modal_Ok), { &C_icon_validate_14, "Approve" });
UX_STEP_CB(ux_step_send_Cancel, pb, EndModal(c_Modal_Cancel), { &C_icon_crossmark, "Reject" });

UX_FLOW(ux_flow_send,
    &ux_step_send_review,
#ifdef TARGET_NANOSP
    & ux_step_send_amount_asset,
    & ux_step_send_fee_type,
#else // TARGET_NANOSP
    &ux_step_send_amount,
    &ux_step_send_asset,
    & ux_step_send_fee,
    & ux_step_send_type,
#endif // TARGET_NANOSP
    &ux_step_send_receiver,
#ifdef TARGET_NANOSP
    & ux_step_send_receiver_x,
#else // TARGET_NANOSP
    & ux_step_send_receiver_1,
    & ux_step_send_receiver_2,
#endif // TARGET_NANOSP
//    &ux_step_send_krnid,
//#ifdef TARGET_NANOSP
//    & ux_step_send_krnid_x,
//#else // TARGET_NANOSP
//    & ux_step_send_krnid_1,
//    & ux_step_send_krnid_2,
//#endif // TARGET_NANOSP
    & ux_step_send_Ok,
    &ux_step_send_Cancel);

UX_STEP_NOCB(ux_step_split_review, bb, { "Please review", "Split transaction" });

UX_FLOW(ux_flow_split,
    &ux_step_split_review,
#ifdef TARGET_NANOSP
    & ux_step_send_fee_type,
#else // TARGET_NANOSP
    & ux_step_send_fee,
    & ux_step_send_type,
#endif // TARGET_NANOSP
    //    &ux_step_send_krnid,
//#ifdef TARGET_NANOSP
//    & ux_step_send_krnid_x,
//#else // TARGET_NANOSP
//    & ux_step_send_krnid_1,
//    & ux_step_send_krnid_2,
//#endif // TARGET_NANOSP
    &ux_step_send_Ok,
    & ux_step_send_Cancel);

uint16_t KeyKeeper_ConfirmSpend(KeyKeeper* p, Amount val, AssetID aid, const UintBig* pPeerID, const TxKernelUser* pUser, const UintBig* pKrnID, uint32_t nFlags)
{
    UNUSED(pKrnID);
    UNUSED(pUser);

    if (c_KeyKeeper_ConfirmSpend_2ndPhase & nFlags)
        return c_KeyKeeper_Status_Ok; // Current decision: ask only on the 1st invocation. Final confirmation isn't needed.


    g_Ux_U.m_Spend.m_Amount = val;
    g_Ux_U.m_Spend.m_Fee = p->u.m_TxBalance.m_TotalFee;
    g_Ux_U.m_Spend.m_Aid = aid;
    g_Ux_U.m_Spend.m_pAddr = pPeerID;
    //g_Ux_U.m_Spend.m_pUser = pUser;
    g_Ux_U.m_Spend.m_Flags = nFlags;
    //g_Ux_U.m_Spend.m_pKrnID = pKrnID;

    ux_flow_init(0, pPeerID ? ux_flow_send : ux_flow_split, NULL);
    uint8_t res = DoModal();
    ui_menu_main();

    return (c_Modal_Ok == res) ? c_KeyKeeper_Status_Ok : c_KeyKeeper_Status_UserAbort;
}



//////////////////////
// progr
/*
UX_STEP_NOCB(ux_step_progr, nn, { "Total added", g_szLine1 });

UX_FLOW(ux_flow_progr,
    &ux_step_progr);

uint32_t g_EccAdded = 0;

void WaitDisplayed();

void UpdProgr()
{
    PrintDecimalAuto(g_szLine1, g_EccAdded);

    ux_flow_init(0, ux_flow_progr, NULL);
    WaitDisplayed();
}

__attribute__((noinline))
void OnEccPointAdd()
{
    g_EccAdded++;

    if (!(g_EccAdded % 500))
        UpdProgr();
}
*/


__attribute__((noinline))
bool InitMasterKey()
{
    uint32_t iAccount = N_Global.m_iAccount;

#define HARDENED_PATH_MASK 0x80000000

    uint32_t pBip44[5] = {
        HARDENED_PATH_MASK | 44,        // Purpose == bip44
        HARDENED_PATH_MASK | 0x5fd,     // Coin type = BEAM
        HARDENED_PATH_MASK | iAccount,  // Account
        0,                              // Change
        0,                              // Addr index
    };

#pragma pack (push, 1)
    union
    {
        uint8_t pNode[64];
        UintBig hv0; // 1st part of the generated node
    } u;
#pragma pack (pop)

    memset(&u, 0, sizeof(u));

    bool bOk = false;

	BEGIN_TRY {
		TRY {

			// Derive node and chain code from path and seed key
            os_perso_derive_node_with_seed_key(HDW_NORMAL, CX_CURVE_SECP256K1, pBip44, sizeof(pBip44) / sizeof(pBip44[0]), u.pNode, 0, 0, 0);

            KeyKeeper* pKk = KeyKeeper_Get();
            memset(pKk, 0, sizeof(*pKk));

            Kdf_Init(&pKk->m_MasterKey, &u.hv0);

            bOk = true;
		}
		
		FINALLY {
            explicit_bzero(&u, sizeof(u));
		}
	}
	END_TRY;

    return bOk;
}




//__stack_hungry__
void ui_menu_initial()
{
    KeyKeeper* pKk = KeyKeeper_Get();
    memset(pKk, 0, sizeof(*pKk));

    if (InitMasterKey())
    {
        UX_INIT();
        if (!G_ux.stack_count)
            ux_stack_push();

        ui_menu_main();
    }
    else
        halt();
}


/*
typedef void (*action_validate_cb)(bool);
static action_validate_cb g_validate_callback;
static char g_amount[30];
static char g_bip32_path[60];
static char g_address[43];

// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_addr_step, pn, {&C_icon_eye, "Confirm Address"});
// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_bip32_path,
             });
// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_address,
             });
// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

// FLOW to display address and BIP32 path:
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display BIP32 Path
// #3 screen: display address
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_addr_step,
        &ux_display_path_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_address() {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_bip32_path, 0, sizeof(g_bip32_path));
    if (!bip32_path_format(G_context.bip32_path,
                           G_context.bip32_path_len,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    memset(g_address, 0, sizeof(g_address));
    uint8_t address[ADDRESS_LEN] = {0};
    if (!address_from_pubkey(G_context.pk_info.raw_public_key, address, sizeof(address))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }
    snprintf(g_address, sizeof(g_address), "0x%.*H", sizeof(address), address);
    g_validate_callback = &ui_action_validate_pubkey;


    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}

// Step with icon and text
UX_STEP_NOCB(ux_display_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Transaction",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = g_amount,
             });

// FLOW to display transaction information:
// #1 screen : eye icon + "Review Transaction"
// #2 screen : display amount
// #3 screen : display destination address
// #4 screen : approve button
// #5 screen : reject button
UX_FLOW(ux_display_transaction_flow,
        &ux_display_review_step,
        &ux_display_address_step,
        &ux_display_amount_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_transaction() {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    memset(g_amount, 0, sizeof(g_amount));
    char amount[30] = {0};
    if (!format_fpu64(amount,
                      sizeof(amount),
                      G_context.tx_info.transaction.value,
                      EXPONENT_SMALLEST_UNIT)) {
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }
    snprintf(g_amount, sizeof(g_amount), "BOL %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    memset(g_address, 0, sizeof(g_address));
    //snprintf(g_address, sizeof(g_address), "0x%.*H", ADDRESS_LEN, G_context.tx_info.transaction.to);

    g_validate_callback = &ui_action_validate_transaction;

    ux_flow_init(0, ux_display_transaction_flow, NULL);

    return 0;
}
*/


void SecureEraseMem(void* p, uint32_t n)
{
	explicit_bzero(p, n);
}

/////////////////////////////////////
// Slots
uint32_t KeyKeeper_getNumSlots()
{
	return c_KeyKeeper_Slots;
}

__attribute__((noinline))
void RegenerateSlot(UintBig* pSlotValue)
{
    // use both rng and prev value to derive the new value
    secp256k1_sha256_t sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, pSlotValue->m_pVal, sizeof(*pSlotValue));

    UintBig hv;
    cx_rng(hv.m_pVal, sizeof(hv));
    secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv));

    secp256k1_sha256_finalize(&sha, hv.m_pVal);

    nvm_write((void*) pSlotValue, hv.m_pVal, sizeof(hv));
}

__attribute__((noinline))
void KeyKeeper_ReadSlot(KeyKeeper* p, uint32_t iSlot, UintBig* pRes)
{
    UNUSED(p);
    assert(iSlot < c_KeyKeeper_Slots);
    UintBig* pSlot = (UintBig*) (N_Global.m_pSlot + iSlot);

    if (IsUintBigZero(pSlot))
        RegenerateSlot(pSlot); // 1st-time access

    memcpy(pRes->m_pVal, pSlot->m_pVal, sizeof(*pSlot));
}

__attribute__((noinline))
void KeyKeeper_RegenerateSlot(KeyKeeper* p, uint32_t iSlot)
{
    UNUSED(p);
    assert(iSlot < c_KeyKeeper_Slots);
    UintBig* pSlot = (UintBig*) (N_Global.m_pSlot + iSlot);

    RegenerateSlot(pSlot);
}

/////////////////////////////////////
// AuxBuf
#ifdef BeamCrypto_ScarceStack

const KeyKeeper_AuxBuf* KeyKeeper_GetAuxBuf(KeyKeeper* pKk)
{
    UNUSED(pKk);
    return (const KeyKeeper_AuxBuf*) &N_Global.m_AuxBuf;
}

void KeyKeeper_WriteAuxBuf(KeyKeeper* pKk, const void* p, uint32_t nOffset, uint32_t nSize)
{
    UNUSED(pKk);
    assert(nOffset + nSize <= sizeof(KeyKeeper_AuxBuf));

    uint8_t* pDst = (uint8_t*) &N_Global.m_AuxBuf;

    nvm_write(pDst + nOffset, (void*) p, nSize);
}

#else // BeamCrypto_ScarceStack

KeyKeeper_AuxBuf g_AuxBuf; // goes to RAM

const KeyKeeper_AuxBuf* KeyKeeper_GetAuxBuf(KeyKeeper* pKk)
{
    UNUSED(pKk);
    return &g_AuxBuf;
}

void KeyKeeper_WriteAuxBuf(KeyKeeper* pKk, const void* p, uint32_t nOffset, uint32_t nSize)
{
    UNUSED(pKk);
    assert(nOffset + nSize <= sizeof(KeyKeeper_AuxBuf));

    uint8_t* pDst = (uint8_t*) &g_AuxBuf;

    memcpy(pDst + nOffset, p, nSize);
}

#endif // BeamCrypto_ScarceStack

void OnBeamHostRequest(uint8_t* pBuf, uint32_t nIn, uint32_t* pOut)
{
    uint16_t errCode = KeyKeeper_Invoke(KeyKeeper_Get(), pBuf, nIn, pBuf, pOut);
    if (c_KeyKeeper_Status_Ok == errCode)
        pBuf[0] = c_KeyKeeper_Status_Ok;
    else
    {
        // return distinguishable error message
        pBuf[0] = (uint8_t) errCode;
        pBuf[1] = (uint8_t) (errCode >> 8);
        pBuf[2] = 'b';
        pBuf[3] = 'F';
        *pOut = 4;
    }
}

UX_STEP_CB(ux_step_alert, bb, EndModal(c_Modal_Ok), { g_szLine1, g_szLine2 });

UX_FLOW(ux_flow_alert,
    &ux_step_alert);

void Alert(const char* sz, uint32_t n)
{
    memcpy(g_szLine1, sz, sizeof(g_szLine1) - 1);
    g_szLine1[sizeof(g_szLine1) - 1] = 0;
    PrintDecimalAuto(g_szLine2, n);

    ux_flow_init(0, ux_flow_alert, NULL);
    DoModal();
    ui_menu_main();
}
