/*
 * Copyright (c) 2020, Armink, <armink.ztl@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _FAL_CFG_H_
#define _FAL_CFG_H_

#define FAL_DEBUG 1
#define FAL_PART_HAS_TABLE_CFG
// #define FAL_USING_SFUD_PORT

/* ===================== Flash device Configuration ========================= */
extern struct fal_flash_dev nor_flash0;

/* flash device table */
#define FAL_FLASH_DEV_TABLE \
    {                       \
        &nor_flash0,        \
    }

#define FAL_PART_NAME_FIRMWARE    "firmware"
#define FAL_PART_NAME_KVDB        "kvdb"
#define FAL_PART_NAME_LITTLEFS    "littlefs"

/* ====================== Partition Configuration ========================== */
#ifdef FAL_PART_HAS_TABLE_CFG
/* partition table */
#define FAL_PART_TABLE                                                                        \
    {                                                                                         \
        {FAL_PART_MAGIC_WORD, FAL_PART_NAME_FIRMWARE,   "nor_flash0",              0,   800  * 1024, 0},   \
        {FAL_PART_MAGIC_WORD, FAL_PART_NAME_KVDB,       "nor_flash0",     848 * 1024,    48  * 1024, 0},   \
        {FAL_PART_MAGIC_WORD, FAL_PART_NAME_LITTLEFS,   "nor_flash0",     896 * 1024,   128  * 1024, 0},   \
    }
#endif /* FAL_PART_HAS_TABLE_CFG */

#endif /* _FAL_CFG_H_ */
