# CS_ARCH_AARCH64, 0, None

0xa0,0xd1,0x3f,0xf8 == ld64b x0, [x13]
0xae,0x91,0x3f,0xf8 == st64b x14, [x13]
0xb4,0xb1,0x21,0xf8 == st64bv x1, x20, [x13]
0xb6,0xa1,0x21,0xf8 == st64bv0 x1, x22, [x13]
0xe0,0xd3,0x3f,0xf8 == ld64b x0, [sp]
0xee,0x93,0x3f,0xf8 == st64b x14, [sp]
0xf4,0xb3,0x21,0xf8 == st64bv x1, x20, [sp]
0xf6,0xa3,0x21,0xf8 == st64bv0 x1, x22, [sp]
0xa0,0xd0,0x38,0xd5 == mrs x0, ACCDATA_EL1
0xa0,0xd0,0x18,0xd5 == msr ACCDATA_EL1, x0
