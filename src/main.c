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
#include <assert.h>

#include "os.h"
#include "ux.h"

#include "types.h"
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "handler/get_public_key.h"
#include "handler/sign_tx.h"

#include "BeamApp.h"
#include "hw_crypto/byteorder.h"

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
global_ctx_t G_context;


uint8_t g_Modal = 0;

uint8_t DoModal()
{
    g_Modal = 0;

    do
    {
        io_seproxyhal_general_status();
        // wait until a SPI packet is available
        // NOTE: on ST31, dual wait ISO & RF (ISO instead of SPI)
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();

    } while (!g_Modal);

    return g_Modal;
}

void EndModal(uint8_t res)
{
    assert(res);
    g_Modal = res;
}

uint32_t OnApduRcv(uint32_t lenInp)
{

     // Structure with fields of APDU command.
#pragma pack (push, 1)
    typedef struct {
        uint8_t cla;    // Instruction class
        command_e ins;  // Instruction code
        uint8_t p1;     // Instruction parameter 1
        uint8_t p2;     // Instruction parameter 2
        uint8_t lc;     // Length of command data
        uint8_t data[0];  // Command data, variable length
    } command_t;
#pragma pack (pop)

    _Static_assert(sizeof(command_t) == 5, "");

    uint16_t retCode = SW_WRONG_DATA_LENGTH;
    uint32_t lenOutp = 0;

    if (lenInp < sizeof(command_t))
    {
        PRINTF("=> /!\\ too short\n");
        OnBeamInvalidRequest();
    }
    else
    {

        command_t* pCmd = (command_t*) G_io_apdu_buffer;
        if (lenInp - sizeof(command_t) != pCmd->lc)
        {
            PRINTF("=> /!\\ Incorrect apdu LC: %.*H\n", lenInp, G_io_apdu_buffer);
            OnBeamInvalidRequest();
        }
        else
        {
            PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
                pCmd->cla,
                pCmd->ins,
                pCmd->p1,
                pCmd->p2,
                pCmd->lc,
                pCmd->lc,
                pCmd->data);

            if (pCmd->cla != CLA)
                retCode = SW_CLA_NOT_SUPPORTED;
            else
            {

            }
        }
    }

    retCode = bswap16_be(retCode);
    memcpy(G_io_apdu_buffer + lenOutp, &retCode, sizeof(retCode));

    return lenOutp + sizeof(retCode);
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

void app_main()
{

	_stack = STACK_MARK;
	
    BeamStackTest1();
    BeamStackTest2();
    //halt();

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

    for (int ioLen = 0; ; )
    {
		PRINTF("Stack canary=%x\n", _stack);
		
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
                ioLen = OnApduRcv(ioLen);
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
