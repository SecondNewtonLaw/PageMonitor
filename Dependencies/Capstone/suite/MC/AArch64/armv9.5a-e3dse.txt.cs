# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = []
0x20,0xc1,0x3e,0xd5 == mrs x0, VDISR_EL3
0x20,0xc1,0x1e,0xd5 == msr VDISR_EL3, x0
0x60,0x52,0x3e,0xd5 == mrs x0, VSESR_EL3
0x60,0x52,0x1e,0xd5 == msr VSESR_EL3, x0
