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

#pragma once

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero
#include <assert.h>

#include "os.h"
#include "ux.h"

// Modal loop emulation
uint8_t DoModal();
void EndModal(uint8_t res);

extern ux_state_t G_ux; // Global structure to perform asynchronous UX aside IO operations.


// unit tests
void BeamStackTest1();
void BeamStackTest2();

void OnBeamInvalidRequest();
uint16_t OnBeamHostRequest(uint8_t* pBuf, uint32_t nIn, uint32_t* pOut);

void ui_menu_main();
void ui_menu_initial(); // can be different from main for testing
void ui_menu_about();
