/*********************************************************************
 * wvcrc32.h
 *
 * (c) Copyright 2011-2012 Google, Inc.
 *
 * Compte CRC32 Checksum. Needed for verification of WV Keybox.
 *********************************************************************/

#ifndef WV_CRC_32_H_
#define WV_CRC_32_H_

#include <stdint.h>

uint32_t wvcrc32(const uint8_t* p_begin, int i_count);
uint32_t wvcrc32n(const uint8_t* p_begin, int i_count);  // Convert to network byte
                                                   // order.

#endif //  WV_CRC_32_H_
