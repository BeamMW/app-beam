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

#include "BeamApp.h"
#include "os_io_seproxyhal.h"
#include "sw.h"
#include "hw_crypto/byteorder.h"

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;


#if ((defined TARGET_NANOX) + (defined TARGET_NANOS) + (defined TARGET_NANOSP) != 1)
#   error inconsistent target defs
#endif

void WaitDisplayed()
{
    UX_WAKE_UP()
    UX_REDISPLAY();
    UX_WAIT_DISPLAYED();
}

void UxSingleCycle()
{
    io_seproxyhal_general_status();
    // wait until a SPI packet is available
    // NOTE: on ST31, dual wait ISO & RF (ISO instead of SPI)
    io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
    io_seproxyhal_handle_event();
}

uint8_t g_Modal = 0;

uint8_t DoModal()
{
    g_Modal = 0;
    PRINTF("Modal begin\n");

    do
    {
        UxSingleCycle();

    } while (!g_Modal);

    PRINTF("Modal end %u\n", (uint32_t) g_Modal);

    return g_Modal;
}

void EndModal(uint8_t res)
{
    assert(res);
    g_Modal = res;
}

uint16_t OnApduRcv(int* pLen)
{
    uint32_t lenInp = *pLen;
    *pLen = 0;

     // Structure with fields of APDU command.
#pragma pack (push, 1)
    typedef struct {
        uint8_t cla;    // Instruction class
        uint8_t ins;    // Instruction code
        uint8_t p1;     // Instruction parameter 1
        uint8_t p2;     // Instruction parameter 2
        uint8_t lc;     // Length of command data
        uint8_t data[0];  // Command data, variable length
    } command_t;
#pragma pack (pop)

    if (lenInp < sizeof(command_t))
    {
        PRINTF("=> /!\\ too short\n");
        return SW_WRONG_DATA_LENGTH;
    }

    command_t* const pCmd = (command_t*) G_io_apdu_buffer;
    lenInp -= sizeof(command_t);

    if (lenInp != pCmd->lc)
    {
        PRINTF("=> /!\\ Incorrect apdu LC: %.*H\n", lenInp, G_io_apdu_buffer);
        return SW_WRONG_DATA_LENGTH;
    }

    PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
        pCmd->cla,
        pCmd->ins,
        pCmd->p1,
        pCmd->p2,
        pCmd->lc,
        pCmd->lc,
        pCmd->data);

    if (pCmd->cla != 0xE0) // CLA
        return SW_CLA_NOT_SUPPORTED;

    if ('B' != pCmd->ins)
        return SW_INS_NOT_SUPPORTED;

    if (pCmd->p1 || pCmd->p2)
        return SW_WRONG_P1P2;

    uint32_t* pSizeOut = (uint32_t *) pLen;
    _Static_assert(sizeof(*pLen) == sizeof(*pSizeOut), "");

    *pSizeOut = sizeof(G_io_apdu_buffer) - sizeof(uint16_t);

    OnBeamHostRequest(G_io_apdu_buffer + sizeof(*pCmd), lenInp, G_io_apdu_buffer, pSizeOut);

    return SW_OK;
}


/**
 * Handle APDU command received and send back APDU response using handlers.
 */

#define STACK_MARK 0xfadebabe

__attribute__((noinline))
void StackMark()
{
#ifdef STACK_CANARY
    uint32_t* pMark = (uint32_t*) &_stack;
    for (; ((uint32_t*) &pMark) - pMark > 20; pMark++)
        (*pMark) = STACK_MARK;
#endif // STACK_CANARY
}

__attribute__((noinline))
void StackPrint(const void* p, const char* sz)
{
    UNUSED(p);
    UNUSED(sz);

#ifdef STACK_CANARY
    uint32_t* pMark = (uint32_t*) &_stack;
    for (; ; pMark++)
        if ((*pMark) != STACK_MARK)
            break;

    PRINTF("@@ Op=%s, Stack consumed: %u\n", sz, (((uint32_t*) p) - pMark) * sizeof(uint32_t));
#endif // STACK_CANARY
}

void app_main()
{
    //BeamStackTest1();
    //BeamStackTest2();
    //halt();

    PRINTF("apdu_ptr=%x\n", G_io_apdu_buffer);
    PRINTF("apdu_len=%u\n", sizeof(G_io_apdu_buffer));
    PRINTF("uxbuf_len=%u\n", sizeof(G_io_seproxyhal_spi_buffer));
    PRINTF("gux_len=%u\n", sizeof(G_ux));
    PRINTF("gux_params_len=%u\n", sizeof(G_ux_params));

#ifdef STACK_CANARY
    _stack = STACK_MARK;
    PRINTF("canary_ptr=%x\n", &_stack);
#endif // STACK_CANARY

    for (int ioLen = 0; ; )
    {
#ifdef STACK_CANARY
		PRINTF("Stack canary=%x\n", _stack);
#endif // STACK_CANARY

        BEGIN_TRY{
            TRY {

                // Receive command bytes in G_io_apdu_buffer
                ioLen = io_exchange(CHANNEL_APDU, ioLen);
                if (ioLen < 0)
                {
                    CLOSE_TRY;
                    return;
                }

                PRINTF("=> Incoming command: %.*H\n", ioLen, G_io_apdu_buffer);

                // Dispatch structured APDU command to handler
                uint16_t sw = OnApduRcv(&ioLen);
                sw = bswap16_be(sw);

                memcpy(G_io_apdu_buffer + ioLen, &sw, sizeof(sw));
                ioLen += sizeof(sw);
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
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

                ui_menu_initial();

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

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *) element);
}

uint8_t io_event(uint8_t channel __attribute__((unused))) {
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
            break;
        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&  //
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &      //
                  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
            /* fallthrough */
        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            UX_DISPLAYED_EVENT({});
            break;
        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
            //PRINTF("OnTick %u\n", G_io_app.ms);
            void OnUiTick();
            OnUiTick();
            break;
        default:
            UX_DEFAULT_EVENT();
            break;
    }

    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    return 1;
}

uint16_t io_exchange_al(uint8_t channel, uint16_t tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    halt();
                }

                return 0;
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
            }
        default:
            THROW(INVALID_PARAMETER);
    }

    return 0;
}
