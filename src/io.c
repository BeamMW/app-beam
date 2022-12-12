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

#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "io.h"
#include "globals.h"
#include "sw.h"
#include "common/buffer.h"
#include "common/write.h"


/**
 * Variable containing the length of the APDU response to send back.
 */
static uint32_t G_output_len = 0;

/**
 * IO state (READY, RECEIVING, WAITING).
 */
static io_state_e G_io_state = READY;

void io_init() {
    // Reset length of APDU response
    G_output_len = 0;
    G_io_state = READY;
}

int io_recv_command() {
    int ret = -1;

    switch (G_io_state) {
        case READY:
            G_io_state = RECEIVED;
            ret = io_exchange(CHANNEL_APDU, G_output_len);
            break;
        case RECEIVED:
            G_io_state = WAITING;
            ret = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, G_output_len);
            G_io_state = RECEIVED;
            break;
        case WAITING:
            G_io_state = READY;
            ret = -1;
            break;
    }

    return ret;
}

int io_send_response(const void* pPtr, unsigned int len, uint16_t sw) {
    int ret = -1;

    if (len)
    {
        if (len > IO_APDU_BUFFER_SIZE - 2)
            return io_send_sw(SW_WRONG_RESPONSE_LENGTH);

        memcpy(G_io_apdu_buffer, pPtr, len);
        G_output_len = len;

        PRINTF("<= SW=%04X | RData=%.*H\n", sw, len, pPtr);
    } else {
        G_output_len = 0;
        PRINTF("<= SW=%04X | RData=\n", sw);
    }

    write_u16_be(G_io_apdu_buffer, G_output_len, sw);
    G_output_len += 2;

    switch (G_io_state) {
        case READY:
            ret = -1;
            break;
        case RECEIVED:
            G_io_state = READY;
            ret = 0;
            break;
        case WAITING:
            ret = io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, G_output_len);
            G_output_len = 0;
            G_io_state = READY;
            break;
    }

    return ret;
}

int io_send_sw(uint16_t sw) {
    return io_send_response(NULL, 0, sw);
}
