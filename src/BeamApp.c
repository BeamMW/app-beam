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

void DeriveAddress(const KeyKeeper* p, AddrID addrID, secp256k1_scalar* pKey, UintBig* pAddr);

__attribute__((noinline))
void DeriveAddress2(const KeyKeeper* p, AddrID addrID, UintBig* pAddr)
{
    secp256k1_scalar sk;
    DeriveAddress(p, addrID, &sk, pAddr);
}

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
        AssetID m_Aid;
        const UintBig* m_pAddr;
        const TxKernelUser* m_pUser;
        //const UintBig* m_pKrnID;

    } m_Spend;

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
// ui Main
UX_STEP_NOCB(ux_step_main_ready, pnn, { &C_beam_logo, "Beam", "is ready" });
UX_STEP_NOCB(ux_step_main_version, bn, { "Version", APPVERSION });
UX_STEP_CB(ux_step_main_about, pb, ui_menu_about(), { &C_icon_certificate, "About" });
UX_STEP_VALID(ux_step_main_quit, pb, os_sched_exit(-1), { &C_icon_dashboard_x, "Quit" });

UX_FLOW(ux_flow_main,
    &ux_step_main_ready,
    &ux_step_main_version,
    &ux_step_main_about,
    &ux_step_main_quit,
    FLOW_LOOP);

void ui_menu_main()
{
    ux_flow_init(0, ux_flow_main, NULL);
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
UX_STEP_NOCB_INIT(ux_step_send_amount, bn, PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_Amount), { "Amount", g_szLine1 });
UX_STEP_NOCB_INIT(ux_step_send_asset, bn, PrintAssetID(g_szLine1, g_Ux_U.m_Spend.m_Aid), { "Asset", g_szLine1 });
UX_STEP_NOCB_INIT(ux_step_send_fee, bn, PrintAmount(g_szLine1, g_Ux_U.m_Spend.m_pUser->m_Fee), { "Fee", g_szLine1 });
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
    &ux_step_send_amount,
    &ux_step_send_asset,
    &ux_step_send_fee,
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
    &ux_step_send_Ok);

UX_STEP_NOCB(ux_step_split_review, bb, { "Please review", "Split transaction" });

UX_FLOW(ux_flow_split,
    &ux_step_split_review,
    &ux_step_send_fee,
//    &ux_step_send_krnid,
//#ifdef TARGET_NANOSP
//    & ux_step_send_krnid_x,
//#else // TARGET_NANOSP
//    & ux_step_send_krnid_1,
//    & ux_step_send_krnid_2,
//#endif // TARGET_NANOSP
    &ux_step_send_Ok);

uint16_t KeyKeeper_ConfirmSpend(KeyKeeper* p, Amount val, AssetID aid, const UintBig* pPeerID, const TxKernelUser* pUser, const UintBig* pKrnID)
{
    UNUSED(p);

    if (pPeerID && pKrnID)
        return c_KeyKeeper_Status_Ok; // Current decision: ask only on the 1st invocation. Final confirmation isn't needed.


    g_Ux_U.m_Spend.m_Amount = val;
    g_Ux_U.m_Spend.m_Aid = aid;
    g_Ux_U.m_Spend.m_pAddr = pPeerID;
    g_Ux_U.m_Spend.m_pUser = pUser;
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

KeyKeeper g_KeyKeeper;

//__stack_hungry__
void ui_menu_initial()
{
    memset(&g_KeyKeeper, 0, sizeof(g_KeyKeeper));

    // TODO: derive our master key
    UintBig hv;
    memset(&hv, 0, sizeof(hv));
    Kdf_Init(&g_KeyKeeper.m_MasterKey, &hv);

    UX_INIT();
    if (!G_ux.stack_count)
        ux_stack_push();

    ui_menu_main();
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
#define c_KeyKeeper_Slots 16
typedef struct
{
    UintBig m_pSlot[c_KeyKeeper_Slots];
} KeyKeeperSlots;

static const KeyKeeperSlots N_Slots; // goes to nvrom

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
    UintBig* pSlot = (UintBig*) (N_Slots.m_pSlot + iSlot);

    if (IsUintBigZero(pSlot))
        RegenerateSlot(pSlot); // 1st-time access

    memcpy(pRes->m_pVal, pSlot->m_pVal, sizeof(*pSlot));
}

__attribute__((noinline))
void KeyKeeper_RegenerateSlot(KeyKeeper* p, uint32_t iSlot)
{
    UNUSED(p);
    assert(iSlot < c_KeyKeeper_Slots);
    UintBig* pSlot = (UintBig*) (N_Slots.m_pSlot + iSlot);

    RegenerateSlot(pSlot);
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






#pragma pack (push, 1)
#define THE_FIELD(type, name) type m_##name;

#define THE_MACRO(id, name) \
typedef struct { uint8_t m_OpCode; BeamCrypto_ProtoRequest_##name(THE_FIELD) } Proto_In_##name; \
typedef struct { uint8_t m_RetVal; BeamCrypto_ProtoResponse_##name(THE_FIELD) } Proto_Out_##name; \
const uint8_t g_Proto_Code_##name = id;

BeamCrypto_ProtoMethods(THE_MACRO)
#undef THE_MACRO
#undef THE_FIELD

#pragma pack (pop)



int KeyKeeper_InvokeExact(KeyKeeper* p, uint8_t* pInOut, uint32_t nIn, uint32_t nOut)
{
    return KeyKeeper_Invoke(p, pInOut, nIn, pInOut, &nOut);
}



void OnSomeDemo()
{
    KeyKeeper kk;
    UintBig hv;
    CompactPoint pPt[2];


    // for fun!
    memset(&hv, 0x11, sizeof(hv));
    Kdf_Init(&kk.m_MasterKey, &hv);

    RangeProof rp;
    memset(&rp, 0, sizeof(rp));

    rp.m_pKdf = &kk.m_MasterKey;

    rp.m_Cid.m_Amount = 400000;
    rp.m_Cid.m_Idx = 15;
    rp.m_Cid.m_Type = 0x22;
    rp.m_Cid.m_SubIdx = 8;
    rp.m_Cid.m_Amount = 4500000000ull;
    rp.m_Cid.m_AssetID = 0;

    memset(pPt, 0, sizeof(pPt));
    rp.m_pT_In = pPt;
    rp.m_pT_Out = pPt;
    rp.m_pTauX = (secp256k1_scalar*)&hv;

    RangeProof_Calculate(&rp);

    KeyKeeper_DisplayAddress(&kk, 15, &hv);

}

void OnBeamHostRequest(uint8_t* pBuf, uint32_t nIn, uint32_t* pOut)
{
    uint16_t errCode = KeyKeeper_Invoke(&g_KeyKeeper, pBuf, nIn, pBuf, pOut);
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

void BeamStackTest1()
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
                secp256k1_ge_storage m_pPt[c_MultiMac_OddCount(c_MultiMac_nBits_Custom)];
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

#ifdef STACK_CANARY
    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &u) - ((uint8_t*) &_stack));
#endif // STACK_CANARY

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
    u.p2.mmCtx.m_Secure.m_Count = 1;
    u.p2.mmCtx.m_Secure.m_pK = &u.p2.s1;
    u.p2.mmCtx.m_Secure.m_pGen = Context_get()->m_pGenGJ;
    u.p2.mmCtx.m_Fast.m_Count = 1;
    u.p2.mmCtx.m_Fast.m_pK = &u.p2.s2;
    u.p2.mmCtx.m_Fast.m_pWnaf = &u.p2.wnaf;
    u.p2.mmCtx.m_Fast.m_pGen0 = Context_get()->m_pGenH;
    u.p2.mmCtx.m_Fast.m_WndBits = c_MultiMac_nBits_H;
    u.p2.mmCtx.m_Fast.m_pZDenom = 0;

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

void BeamStackTest2()
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

            union {
                Proto_In_CreateOutput m_In;
                Proto_Out_CreateOutput m_Out;
            } p6;

        } u;

    } s;

#ifdef STACK_CANARY
    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &s) - ((uint8_t*) &_stack));
#endif // #ifdef STACK_CANARY

    memset(&s.u.hv, 0, sizeof(s.u.hv));
    memset(&s.kk1, 0, sizeof(s.kk1));
    Kdf_Init(&s.kk1.m_MasterKey, &s.u.hv);

    s.u.hv.m_pVal[0] = 4;
    memset(&s.kk2, 0, sizeof(s.kk2));
    Kdf_Init(&s.kk2.m_MasterKey, &s.u.hv);

    StackMark();

    s.u.p1.m_In.m_OpCode = g_Proto_Code_GetNumSlots;
    int n = KeyKeeper_InvokeExact(&s.kk1, (uint8_t*) &s.u.p2, sizeof(s.u.p2.m_In), sizeof(Proto_Out_TxAddCoins));

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
    n = KeyKeeper_InvokeExact(&s.kk1, (uint8_t*) &s.u.p2, sizeof(s.u.p2), sizeof(Proto_Out_TxAddCoins));
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
    n = KeyKeeper_InvokeExact(&s.kk2, (uint8_t*) &s.u.p2, sizeof(s.u.p2), sizeof(Proto_Out_TxAddCoins));
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
    DeriveAddress2(&s.kk2, 102, &s.u.p3.m_In.m_Mut.m_Peer);
    s.u.p3.m_In.m_Mut.m_AddrID = 101;
    s.u.p3.m_In.m_iSlot = 2;

    StackMark();
    n = KeyKeeper_InvokeExact(&s.kk1, (uint8_t*) &s.u.p3, sizeof(s.u.p3.m_In), sizeof(s.u.p3.m_Out));
    StackPrint(&s, "TxSend1");
    PRINTF("ret=%d\n", n);
    Alert("TxSend1", n);

    s.m_TxAux.m_Comms = s.u.p3.m_Out.m_Comms;
    s.m_hvUserAggr = s.u.p3.m_Out.m_UserAgreement;

    s.u.p4.m_In.m_OpCode = g_Proto_Code_TxReceive;
    s.u.p4.m_In.m_Tx.m_Krn.m_Fee = 8;
    s.u.p4.m_In.m_Tx.m_Krn.m_hMin = 100500;
    s.u.p4.m_In.m_Tx.m_Krn.m_hMax = 100600;
    DeriveAddress2(&s.kk1, 101, &s.u.p4.m_In.m_Mut.m_Peer);

    s.u.p4.m_In.m_Mut.m_AddrID = 102;
    s.u.p4.m_In.m_Comms = s.m_TxAux.m_Comms;

    StackMark();
    n = KeyKeeper_InvokeExact(&s.kk2, (uint8_t*) &s.u.p4, sizeof(s.u.p4.m_In), sizeof(s.u.p4.m_Out));
    StackPrint(&s, "TxReceive");
    PRINTF("ret=%d\n", n);
    Alert("TxReceive", n);

    memmove(&s.u.p5.m_In.m_PaymentProof, &s.u.p4.m_Out.m_PaymentProof, sizeof(s.u.p5.m_In.m_PaymentProof));

    s.m_TxAux = s.u.p4.m_Out.m_Tx;

    s.u.p5.m_In.m_OpCode = g_Proto_Code_TxSend2;
    s.u.p5.m_In.m_Tx.m_Krn.m_Fee = 8;
    s.u.p5.m_In.m_Tx.m_Krn.m_hMin = 100500;
    s.u.p5.m_In.m_Tx.m_Krn.m_hMax = 100600;
    DeriveAddress2(&s.kk2, 102, &s.u.p5.m_In.m_Mut.m_Peer);
    s.u.p5.m_In.m_Mut.m_AddrID = 101;
    s.u.p5.m_In.m_iSlot = 2;
    s.u.p5.m_In.m_Comms = s.m_TxAux.m_Comms;
    s.u.p5.m_In.m_UserAgreement = s.m_hvUserAggr;

    StackMark();
    n = KeyKeeper_InvokeExact(&s.kk1, (uint8_t*) &s.u.p5, sizeof(s.u.p5.m_In), sizeof(s.u.p5.m_Out));
    StackPrint(&s, "TxSend2");
    PRINTF("ret=%d\n", n);
    Alert("TxSend2", n);

    memset(&s.u.p6, 0, sizeof(s.u.p6));
    s.u.p6.m_In.m_OpCode = g_Proto_Code_CreateOutput;
    s.u.p6.m_In.m_Cid.m_Amount = 400000;
    s.u.p6.m_In.m_Cid.m_Idx = 15;
    s.u.p6.m_In.m_Cid.m_Type = 0x22;
    s.u.p6.m_In.m_Cid.m_SubIdx = 8;
    s.u.p6.m_In.m_Cid.m_Amount = 4500000000ull;
    s.u.p6.m_In.m_Cid.m_AssetID = 0;

    StackMark();
    n = KeyKeeper_InvokeExact(&s.kk1, (uint8_t*)&s.u.p6, sizeof(s.u.p6.m_In), sizeof(s.u.p6.m_Out));
    StackPrint(&s, "CreateOutput");
    PRINTF("ret=%d\n", n);
    Alert("CreateOutput", n);
}

void BeamStackTest3()
{
    struct
    {
        KeyKeeper kk;

        union
        {
            UintBig hv;

            Proto_In_CreateShieldedVouchers reqVouchers;

            struct {
                Proto_Out_CreateShieldedVouchers m_Out;
                ShieldedVoucher m_Voucher;
            } resVouchers;

            struct {
                Proto_In_TxAddCoins m_Msg;
                ShieldedInput_Blob m_Blob;
                ShieldedInput_Fmt m_Fmt;
            } reqShieldedCoin;

            Proto_In_TxAddCoins m_Out_ShieldedCoin;
        } u;

    } s;

#ifdef STACK_CANARY
    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &s) - ((uint8_t*) &_stack));
#endif // #ifdef STACK_CANARY

    memset(&s, 0, sizeof(s));
    memset(&s.kk, 0, sizeof(s.kk));
    Kdf_Init(&s.kk.m_MasterKey, &s.u.hv);


    StackMark();

    s.u.reqVouchers.m_OpCode = g_Proto_Code_CreateShieldedVouchers;
    s.u.reqVouchers.m_Count = 1;
    int n = KeyKeeper_InvokeExact(&s.kk, (uint8_t*) &s.u.reqVouchers, sizeof(s.u.reqVouchers), sizeof(s.u.resVouchers));

    StackPrint(&s, "CreateVouchers");

    PRINTF("CreateVouchers, ret=%d\n", n);

    memset(&s.u.reqShieldedCoin, 0, sizeof(s.u.reqShieldedCoin));

    s.u.reqShieldedCoin.m_Msg.m_OpCode = g_Proto_Code_TxAddCoins;
    s.u.reqShieldedCoin.m_Msg.m_Reset = 1;
    s.u.reqShieldedCoin.m_Msg.m_InsShielded = 1;

    s.u.reqShieldedCoin.m_Fmt.m_Amount = 9000000000ull;
    s.u.reqShieldedCoin.m_Fmt.m_AssetID = 14;
    s.u.reqShieldedCoin.m_Fmt.m_nViewerIdx = 2;

    StackMark();

    n = KeyKeeper_InvokeExact(&s.kk, (uint8_t*)&s.u.reqShieldedCoin, sizeof(s.u.reqShieldedCoin), sizeof(s.u.m_Out_ShieldedCoin));

    StackPrint(&s, "AddShieldedInput");

    PRINTF("AddShieldedInput, ret=%d\n", n);
}

