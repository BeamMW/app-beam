#pragma once

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero
#include <assert.h>

#include "os.h"
#include "ux.h"

// Modal loop emulation
uint8_t DoModal();
void EndModal(uint8_t res);

// unit tests
void BeamStackTest1();
void BeamStackTest2();

void OnBeamInvalidRequest();
uint16_t OnBeamHostRequest(uint8_t* pBuf, uint32_t nIn, uint32_t* pOut);

void ui_menu_main();

extern ux_state_t G_ux; // Global structure to perform asynchronous UX aside IO operations.
