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

//#if (defined STACK_CANARY) && (defined BeamCrypto_ScarceStack)
//
//KeyKeeper* KeyKeeper_Get()
//{
//    size_t pPtr = (size_t) &_stack;
//
//    // align up
//    if (7 & pPtr)
//        pPtr = (pPtr + 7) & ~7;
//
//    return (KeyKeeper*) pPtr;
//}
//
//#else // STACK_CANARY

KeyKeeper g_KeyKeeper;
KeyKeeper* KeyKeeper_Get()
{
    return &g_KeyKeeper;
}

//#endif // STACK_CANARY


//__stack_hungry__
void ui_menu_initial()
{
    KeyKeeper* pKk = KeyKeeper_Get();
    memset(pKk, 0, sizeof(*pKk));

    // TODO: derive our master key
    UintBig hv;
    memset(&hv, 0, sizeof(hv));
    Kdf_Init(&pKk->m_MasterKey, &hv);

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

/////////////////////////////////////
// AuxBuf
#ifdef BeamCrypto_ScarceStack

static const KeyKeeper_AuxBuf N_AuxBuf; // goes to nvrom

const KeyKeeper_AuxBuf* KeyKeeper_GetAuxBuf(KeyKeeper* pKk)
{
    UNUSED(pKk);
    return &N_AuxBuf;
}

void KeyKeeper_WriteAuxBuf(KeyKeeper* pKk, const void* p, uint32_t nOffset, uint32_t nSize)
{
    UNUSED(pKk);
    assert(nOffset + nSize <= sizeof(KeyKeeper_AuxBuf));

    uint8_t* pDst = (uint8_t*) &N_AuxBuf;

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

void memcpy_unaligned(void* pDst, const void* pSrc, uint32_t n);

void BeamStackTest4()
{
    KeyKeeper* pKk = KeyKeeper_Get();
    memset(pKk, 0, sizeof(*pKk));

    UintBig hv;
    memset(hv.m_pVal, 0, sizeof(hv.m_pVal));
    Kdf_Init(&pKk->m_MasterKey, &hv);


#ifdef STACK_CANARY
    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &hv) - ((uint8_t*) &_stack));
#endif // #ifdef STACK_CANARY

    // test CreateShieldedInput
    {
        Proto_In_CreateShieldedInput_1* pIn = (Proto_In_CreateShieldedInput_1*) G_io_apdu_buffer;
        memset(pIn, 0, sizeof(*pIn));
        pIn->m_OpCode = g_Proto_Code_CreateShieldedInput_1;

        {
            ShieldedInput_Fmt fmt;
            fmt.m_Amount = 43300;
            fmt.m_AssetID = 15;
            fmt.m_nViewerIdx = 443;

            memcpy_unaligned(&pIn->m_InpFmt, &fmt, sizeof(fmt));
        }

        {
            ShieldedInput_SpendParams sp;
            sp.m_hMin = 431000;
            sp.m_hMax = 432000;
            sp.m_WindowEnd = 4672342;
            sp.m_Sigma_M = 8;
            sp.m_Sigma_n = 4;

            memcpy_unaligned(&pIn->m_SpendParams, &sp, sizeof(sp));
        }

        Proto_Out_CreateShieldedInput_1* pOut = (Proto_Out_CreateShieldedInput_1*) G_io_apdu_buffer;

        StackMark();

        int n = KeyKeeper_InvokeExact(pKk, (uint8_t*) pIn, sizeof(*pIn), sizeof(*pOut));

        StackPrint(&hv, "CreateShieldedInput_1");

        PRINTF("CreateShieldedInput_1, ret=%d\n", n);
    }

    {
        Proto_In_CreateShieldedInput_2* pIn = (Proto_In_CreateShieldedInput_2*) G_io_apdu_buffer;
        memset(pIn, 0, sizeof(*pIn));
        pIn->m_OpCode = g_Proto_Code_CreateShieldedInput_2;

        Proto_Out_CreateShieldedInput_2* pOut = (Proto_Out_CreateShieldedInput_2*) G_io_apdu_buffer;

        StackMark();

        int n = KeyKeeper_InvokeExact(pKk, (uint8_t*) pIn, sizeof(*pIn), sizeof(*pOut));

        StackPrint(&hv, "CreateShieldedInput_2");

        PRINTF("CreateShieldedInput_2, ret=%d\n", n);
    }

    {
        Proto_In_CreateShieldedInput_3* pIn = (Proto_In_CreateShieldedInput_3*) G_io_apdu_buffer;
        memset(pIn, 0, sizeof(*pIn));
        pIn->m_OpCode = g_Proto_Code_CreateShieldedInput_3;

        Proto_Out_CreateShieldedInput_3* pOut = (Proto_Out_CreateShieldedInput_3*) G_io_apdu_buffer;

        StackMark();

        int n = KeyKeeper_InvokeExact(pKk, (uint8_t*) pIn, sizeof(*pIn) + sizeof(CompactPoint) * 8, sizeof(*pOut));

        StackPrint(&hv, "CreateShieldedInput_3");

        PRINTF("CreateShieldedInput_3, ret=%d\n", n);
    }

}

void BeamStackTest5()
{
    KeyKeeper* pKk = KeyKeeper_Get();
    memset(pKk, 0, sizeof(*pKk));

    UintBig hv;
    memset(hv.m_pVal, 0, sizeof(hv.m_pVal));
    Kdf_Init(&pKk->m_MasterKey, &hv);


#ifdef STACK_CANARY
    PRINTF("@@ Stack available: %u\n", ((uint8_t*) &hv) - ((uint8_t*) &_stack));
#endif // #ifdef STACK_CANARY



    static const uint8_t pMsg0[] = { 0x18,0x01,0x02,0x01,0x01,0xc7,0xd6,0x86,0x0a,0x38,0x31,0xac,0x35,0x6d,0x72,0x6f,0x6e,0x00,0x00,0x00,0x01,0xe0,0xc8,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1a,0x9c,0x73,0x0c,0x52,0xff,0x72,0xd9,0x6d,0x72,0x6f,0x6e,0x00,0x00,0x00,0x01,0x30,0x88,0x01,0x00,0x00,0x00,0x00,0x00,0x78,0x56,0x34,0x12,0x3e,0xb7,0x0c,0x02,0xb1,0xa1,0xc9,0x9e,0x6d,0x72,0x6f,0x6e,0x00,0x00,0x00,0x01,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x69,0xdb,0xb6,0xc3,0x30,0xe1,0xd6,0x0e,0x8e,0x44,0x70,0x38,0x6b,0xe3,0x37,0x37,0xae,0x93,0xfb,0xad,0x47,0x14,0xcd,0x75,0x73,0x44,0x64,0x7c,0x3b,0x93,0xbf,0xd3,0xd3,0x08,0xee,0xdb,0xab,0x21,0xfd,0xe1,0x43,0xa0,0xea,0x17,0xe2,0x3e,0xdc,0x1f,0x74,0xcb,0xb3,0x63,0x8a,0x20,0x33,0xaa,0xa1,0x54,0x64,0xea,0xa7,0x33,0x38,0x5d,0xbb,0xeb,0x6f,0xd7,0x35,0x09,0xb8,0x57,0xe6,0xa4,0x19,0xdc,0xa1,0xd8,0x90,0x7a,0xf9,0x77,0xfb,0xac,0x4d,0xfa,0x35,0xec,0x02,0xbe,0x82,0x81,0x10,0x6d,0x2d,0x99,0xc0,0xb9,0x6f,0x97,0xb4,0x51,0x93,0xae,0x27,0x0d,0x58,0xaf,0x76,0x6c,0x97,0x1f,0xdf,0x41,0x25,0x8d,0x89,0xa9,0xfb,0x22,0xc5,0x40,0x94,0x7a,0x94,0x95,0x97,0xb2,0x00,0x90,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x2c,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc3,0xb6,0xdb,0x69 };
    static const uint8_t pMsg1[] = { 0x28,0x00,0x00,0xe6,0x00,0x27,0x01,0x84,0xd1,0x08,0x5c,0xe3,0x26,0x17,0x20,0xe5,0x10,0x61,0x1e,0xc4,0x28,0x46,0x59,0x4f,0x11,0x43,0x33,0x0c,0x63,0xf4,0x30,0xdd,0xd7,0xe5,0x45,0x9f,0xed,0xa0,0x60,0x8b,0x8f,0x4b,0x68,0x6d,0x1b,0x02,0x1b,0x64,0xd0,0xef,0x7e,0x20,0xcb,0xe5,0x36,0x3b,0xb3,0x92,0x5d,0x85,0x16,0x9b,0x75,0x94,0xfa,0x6f,0x49,0xc2,0xab,0x1e,0xed,0xf3,0xeb,0x85,0x51,0xfe,0x94,0xd8,0xa3,0x16,0x27,0xff,0x59,0x64,0xe1,0x81,0xf1,0x01,0x3a,0x11,0xab,0xb9,0x6f,0xa2,0x3c,0xb1,0x8c,0xe2,0x91,0x83,0x5c,0x78,0x13,0x73,0x49,0x46,0x36,0x89,0xa1,0x44,0x53,0x82,0x99,0x8f,0x91,0x46,0x54,0x92,0x56,0x66,0x6e,0xfb,0x33,0x3a,0xf6,0xf7,0x8b,0x0c,0x2f,0x4d,0x39,0xfb,0xfd,0x50,0xb8,0x4d,0x17,0xc4,0xa6,0x46,0x3a,0xb6,0xbb,0x83,0x94,0xea,0x62,0x93,0x8b,0x40,0x48,0x36,0x75,0x41,0xd5,0x4e,0x18,0x11,0xbf,0x04,0x3a,0xa5,0x3b,0x9a,0x55,0x22,0xa7,0x80,0xf3,0x1a,0x5d,0xe1,0x0a,0x96,0x54,0x48,0xab,0xd5,0x70,0xa4,0xb9,0x0d,0x7a,0x2e,0xac,0x24,0x3b,0x98,0xde,0x43,0x39,0xe8,0xdd,0xfe,0xc0,0x4f,0x14,0xbf,0x1b,0x03,0xd9,0x2f,0x57,0xd6,0x7f,0xd3,0x66,0x57,0xb0,0xc4,0x8f,0x1c,0x65,0xf6,0x20,0xd7,0x84,0xf3,0x1c,0xd0,0x30,0xa4,0x4d,0x95,0xb9,0xc4,0x19,0xcb,0xaa,0x4b,0x6a,0xdc,0x5d,0x58,0xa6 };
    static const uint8_t pMsg2[] = { 0x28,0xe6,0x00,0xe6,0x00,0x2e,0xf1,0x06,0xde,0x8a,0x42,0x33,0x5b,0x09,0x36,0x4c,0x3b,0x64,0x23,0xf5,0xb1,0x53,0xb9,0xe5,0xc0,0xfc,0x25,0x88,0x86,0xd3,0xdb,0xbe,0x22,0xee,0xe2,0x73,0x65,0xf5,0x91,0xe2,0x3c,0xfb,0x8f,0xba,0x88,0x6a,0xa0,0x7a,0x49,0x42,0x49,0xc8,0xe0,0x2e,0xc1,0xb2,0x2d,0xde,0xa2,0x64,0xc2,0xc2,0xc2,0x3f,0xa8,0x49,0x9c,0x27,0xce,0x56,0x6d,0xa5,0xc6,0xd1,0x5a,0xb9,0x7d,0x2e,0xc2,0x33,0xbe,0x21,0xb5,0x3d,0xa6,0xe5,0x59,0x07,0xaa,0xe3,0xbd,0x39,0xb3,0xa1,0x2d,0x16,0x45,0xef,0x8e,0x59,0x14,0x0f,0x62,0x58,0x62,0xd0,0x51,0x02,0x59,0xe5,0x71,0xb7,0xcc,0x92,0xfd,0x91,0xf2,0x12,0x23,0xaa,0x5a,0x19,0xe8,0xf8,0x6c,0x81,0x79,0x39,0x02,0x62,0xb6,0x47,0xea,0x7d,0x5f,0x5b,0x30,0x82,0x2b,0x70,0xce,0x68,0x0f,0x48,0x7d,0xcb,0xef,0x15,0x4d,0x3a,0x9b,0xe5,0xfc,0xd9,0xca,0x6a,0x80,0xe6,0x66,0xb9,0xa7,0x3e,0x0a,0x43,0x62,0x24,0x3f,0xfb,0x92,0x07,0x1a,0x15,0x76,0x0a,0x59,0x50,0x74,0x42,0xef,0x17,0xa3,0x07,0x71,0x09,0x5f,0xab,0xb5,0x44,0x43,0x3d,0x59,0x45,0xdf,0x90,0xe1,0xe8,0xf4,0xef,0x54,0xa6,0x11,0x64,0x79,0x23,0xdc,0x39,0x4d,0x28,0x82,0x00,0x9e,0xfc,0x75,0x19,0x73,0x62,0x7c,0x16,0xc8,0xcd,0xbe,0xa1,0xfe,0xbf,0x69,0x44,0xcb,0x1b,0x0d,0x76,0xfc,0x7f,0x0e,0xe4,0x7a };
    static const uint8_t pMsg3[] = { 0x28,0xcc,0x01,0xe6,0x00,0x67,0xba,0x17,0x04,0x4f,0x27,0x82,0x47,0xfd,0x4a,0xcb,0x06,0x1c,0xac,0xbe,0xf3,0x40,0xdb,0xdf,0x61,0x5b,0xdc,0x12,0x05,0x18,0x51,0x80,0xe1,0xf8,0xac,0xb1,0xa9,0x2a,0x98,0xda,0xf3,0xad,0x9b,0xd3,0x9f,0x78,0xcb,0xa4,0xff,0x73,0x93,0xe7,0xae,0x87,0xb3,0x5f,0xad,0x0d,0x20,0xf8,0x53,0x14,0xb3,0xdc,0xd8,0x72,0xb7,0x61,0xc6,0xf3,0xd7,0xbc,0x88,0x26,0xc5,0xf1,0x6a,0x33,0xce,0x8c,0x0d,0x4c,0x04,0x7a,0x06,0x22,0x12,0x00,0x57,0x4f,0x6d,0x4a,0xc5,0x5f,0x03,0x52,0x01,0x8e,0x6c,0x82,0xa0,0xc8,0x33,0xdc,0x4a,0xc9,0x78,0xe0,0xec,0x0a,0x72,0xe7,0x2f,0xcd,0xcf,0x48,0x4f,0x74,0x28,0x67,0xc8,0x66,0x40,0xfb,0xef,0x70,0x9e,0xe1,0xfc,0x51,0xa7,0x0b,0x9a,0xa4,0x3a,0xcf,0x65,0x35,0x95,0xf3,0x1d,0x83,0x3b,0xfc,0x37,0x37,0xa7,0x17,0xdf,0xc5,0x8d,0x05,0x61,0xae,0x29,0xc2,0x03,0xe2,0xf7,0x97,0x62,0x6c,0xa6,0x2b,0x66,0xad,0x96,0xa2,0xa3,0xa2,0x76,0x9c,0x4f,0xab,0x45,0xc0,0xb0,0x01,0x67,0x6d,0x7c,0xfb,0xd5,0x2b,0x51,0xfe,0x08,0x46,0xb7,0x8f,0x53,0xae,0x40,0x59,0xd7,0x26,0x50,0xc5,0x7a,0xd7,0x51,0x8a,0xef,0x9d,0x37,0xf4,0xd7,0xfd,0x60,0x12,0xff,0x14,0x65,0xa8,0x7b,0xbe,0x5a,0xc5,0x41,0xb2,0xa3,0xf9,0xac,0x2e,0xeb,0x75,0x27,0xbd,0xa3,0xd6,0xb4,0x8c,0x40,0x3a,0xea };
    static const uint8_t pMsg4[] = { 0x28,0xb2,0x02,0xd3,0x00,0x61,0xf6,0x00,0xfa,0xde,0xaa,0x1c,0x69,0xe3,0x1c,0xfb,0x68,0xfb,0xe3,0xa2,0xff,0x00,0xf7,0x22,0x72,0x23,0x08,0x2a,0x17,0xa7,0x8a,0xd3,0xf1,0x57,0xc1,0xdc,0x15,0xb2,0x10,0xb9,0xfb,0xc6,0x10,0xc6,0x6c,0x0e,0x79,0x55,0xa4,0xb3,0xc2,0xe9,0xc5,0x4e,0x01,0x13,0x67,0x3d,0xbf,0xd2,0x97,0xd5,0x96,0x44,0x99,0x64,0xee,0x55,0x53,0x62,0x3d,0x13,0xc8,0xfe,0x81,0x6b,0x26,0x72,0x46,0x61,0xbb,0x2c,0x6c,0xd3,0xb6,0x70,0xa5,0x93,0x53,0xf7,0xf8,0x30,0x57,0xb2,0x37,0xe7,0x1b,0xfc,0x76,0x2f,0x79,0xb8,0x57,0x68,0x84,0x35,0xab,0xd7,0x9c,0x19,0x44,0x2d,0x4f,0xa8,0x0c,0x41,0xd0,0x2b,0xc1,0xa5,0xe4,0xb6,0xaf,0x20,0x5d,0xc1,0xb8,0xfd,0xe7,0xd9,0xfb,0x2f,0x25,0x64,0x8d,0xaa,0x4e,0x6a,0x74,0x9f,0xbb,0xde,0xc2,0x8d,0x6b,0xa0,0xa0,0x3a,0x75,0xcf,0x0f,0x8d,0x0c,0xfe,0x00,0x7f,0xfa,0x20,0x8f,0x75,0x17,0xfe,0x4e,0x2b,0xb2,0x36,0xc3,0x6c,0xbf,0x2f,0x25,0xdf,0x7d,0x3b,0x9d,0xaa,0x95,0x0e,0x61,0x34,0x39,0x58,0x0a,0x00,0x16,0x33,0xe5,0x50,0x60,0x88,0x7e,0x30,0x53,0x95,0x30,0x10,0x75,0x04,0x44,0x64,0x30,0x7e,0x0f,0xe5,0x6c,0x28,0x2e,0x0f,0x50,0xb7,0x32,0x1a,0x46,0xd1,0x64,0x8b };
    static const uint8_t pMsg5[] = { 0x36,0xe0,0xc8,0x10,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xde,0x5b,0x2e,0x17,0xe9,0x01,0x83,0xf8,0xcd,0x6c,0x46,0x27,0xa7,0x40,0x43,0x0e,0x2a,0x67,0xe7,0x50,0x40,0xd3,0x0e,0xf8,0x05,0x9f,0xdd,0xf4,0xa1,0x6b,0xb5,0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x33,0xd0,0x0b,0x9a,0xdd,0x30,0x10,0x54,0x88,0xdd,0x3d,0x75,0x77,0x61,0x02,0x73,0xd2,0x92,0xec,0x7e,0x9a,0xb9,0x30,0xc0,0xe2,0xf4,0x88,0xe4,0x3d,0xd9,0x3d,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xf4,0x69,0x31,0xac,0xf8,0x4f,0x46,0x5a,0x64,0xe6,0x2c,0xe7,0x40,0x07,0xe9,0x91,0xe3,0x7e,0xa8,0x23,0xfa,0x0f,0xb2,0x19,0x23,0xb7,0x99,0x05,0xb7,0x33,0xb6,0x31,0xe6,0xc5,0x41,0x16,0x7e,0xd8,0xa2,0xb3,0x43,0xb3,0xdc,0x8c,0x5e,0xce,0x77,0xae,0x7f,0x0d,0x97,0xb9,0x31,0x95,0xb1,0xde,0xcd,0x1d,0x11,0x5f,0x16,0xb6,0xba,0x86,0xba,0x00,0x00 };

    StackMark();

    uint32_t nOut = sizeof(G_io_apdu_buffer);
    int n = KeyKeeper_Invoke(pKk, pMsg0, sizeof(pMsg0), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_0");
    PRINTF("SendShielded_0, ret=%d, size=%d\n", n, nOut);

    StackMark();

    nOut = sizeof(G_io_apdu_buffer);
    n = KeyKeeper_Invoke(pKk, pMsg1, sizeof(pMsg1), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_1");
    PRINTF("SendShielded_1, ret=%d, size=%d\n", n, nOut);

    StackMark();

    nOut = sizeof(G_io_apdu_buffer);
    n = KeyKeeper_Invoke(pKk, pMsg2, sizeof(pMsg2), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_2");
    PRINTF("SendShielded_2, ret=%d, size=%d\n", n, nOut);

    StackMark();

    nOut = sizeof(G_io_apdu_buffer);
    n = KeyKeeper_Invoke(pKk, pMsg3, sizeof(pMsg3), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_3");
    PRINTF("SendShielded_3, ret=%d, size=%d\n", n, nOut);

    StackMark();

    nOut = sizeof(G_io_apdu_buffer);
    n = KeyKeeper_Invoke(pKk, pMsg4, sizeof(pMsg4), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_4");
    PRINTF("SendShielded_4, ret=%d, size=%d\n", n, nOut);

    StackMark();

    nOut = sizeof(G_io_apdu_buffer);
    n = KeyKeeper_Invoke(pKk, pMsg5, sizeof(pMsg5), G_io_apdu_buffer, &nOut);

    StackPrint(&hv, "SendShielded_5");
    PRINTF("SendShielded_5, ret=%d, Data=%.*H\n", n, nOut, G_io_apdu_buffer);
}
