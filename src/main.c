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

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
global_ctx_t G_context;


int OnApduRcv(unsigned int rcvLen)
{
    _Static_assert(sizeof(command_t) == 5, "");

    command_t* pCmd = (command_t*) G_io_apdu_buffer;
    if ((rcvLen < sizeof(command_t)) || (rcvLen - sizeof(command_t) != pCmd->lc))
    {
        PRINTF("=> /!\\ BAD LENGTH: %.*H\n", rcvLen, G_io_apdu_buffer);
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return 0; // ignore
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
        _Static_assert(sizeof(pRes) == APPVERSION_LEN);

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
void app_main() {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;

    io_init();

    // Reset context
    explicit_bzero(&G_context, sizeof(G_context));

    for (;;) {
        BEGIN_TRY {
            TRY {

                // Receive command bytes in G_io_apdu_buffer
                if ((input_len = io_recv_command()) < 0) {
                    CLOSE_TRY;
                    return;
                }


                // Dispatch structured APDU command to handler
                if (OnApduRcv(input_len) < 0) {
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
