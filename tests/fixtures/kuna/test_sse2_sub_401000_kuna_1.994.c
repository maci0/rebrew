bool sub_401000(void)
{
  char *s; // eax | stack - 0x134
  unsigned int v2; // eax
  unsigned int v3; // ecx
  int v4; // ecx
  double v5; // ram 0x42c000 | ram 0x42c090 | ram 0x42c130 | ram 0x42c140 | stack - 0x120 | stack - 0xa0 | xmm0_qa | xmm1_qa | xmm2_qa | xmm3_qa
  double v6 [17]; // ram 0x42c008 | ram 0x42c138 | stack - 0x98 | xmm0_qa | xmm1_qa
  unsigned int v7; // ram 0x42c0e0 | stack - 0xe0
  int v8; // esi | stack - 0x134
  int v9; // edi | stack - 0x138
  bool v10; // zf
  unsigned int v11; // ram 0x42c0a8 | ram 0x42c128 | stack - 0x118
  unsigned int v12; // ram 0x42c0ac | ram 0x42c12c | stack - 0x114
  unsigned int v13; // ram 0x42c0b0 | ram 0x42c120 | stack - 0x110 | stack - 0x120
  unsigned int v14; // ram 0x42c0b4 | ram 0x42c124 | stack - 0x10c | stack - 0x11c
  unsigned int v15; // ram 0x42c0b8 | ram 0x42c128 | stack - 0x108
  unsigned int v16; // ram 0x42c0bc | ram 0x42c12c | stack - 0x104
  unsigned int v17; // ram 0x42c0c0 | ram 0x42c120 | stack - 0x100 | stack - 0x120
  unsigned int v18; // ram 0x42c0c4 | ram 0x42c124 | stack - 0x11c | stack - 0xfc
  unsigned int v19; // ram 0x42c0c8 | ram 0x42c128 | stack - 0xf8
  unsigned int v20; // ram 0x42c0cc | ram 0x42c12c | stack - 0xf4
  unsigned int v21; // ram 0x42c0d0 | ram 0x42c120 | stack - 0x120 | stack - 0xf0
  unsigned int v22; // ram 0x42c0d4 | ram 0x42c124 | stack - 0x11c | stack - 0xec
  unsigned int v23; // ram 0x42c0d8 | ram 0x42c128 | stack - 0xe8
  unsigned int v24; // ram 0x42c0dc | ram 0x42c12c | stack - 0xe4
  unsigned int v25; // ram 0x42c0e4 | stack - 0xdc
  unsigned int v26; // ram 0x42c0e8 | stack - 0xd8
  unsigned int v27; // ram 0x42c0ec | stack - 0xd4
  unsigned int v28; // ram 0x42c0f0 | stack - 0xd0
  unsigned int v29; // ram 0x42c0f4 | stack - 0xcc
  unsigned int v30; // ram 0x42c0f8 | stack - 0xc8
  unsigned int v31; // ram 0x42c0fc | stack - 0xc4
  unsigned int v32; // ram 0x42c100 | stack - 0xc0
  unsigned int v33; // ram 0x42c104 | stack - 0xbc
  unsigned int v34; // ram 0x42c108 | stack - 0xb8
  unsigned int v35; // ram 0x42c10c | stack - 0xb4
  unsigned int v36; // ram 0x42c110 | stack - 0xb0
  unsigned int v37; // ram 0x42c114 | stack - 0xac
  unsigned int v38; // ram 0x42c118 | stack - 0xa8
  unsigned int v39; // ram 0x42c11c | stack - 0xa4
  double v40; // ram 0x42c130 | stack - 0x120 | stack - 0xa0 | xmm0_qa

  sub_401aa0();
  puts("=== SSE2 Test Suite ===\n");
  sub_402120("1. Double arithmetic ... ");
  fflush((void *)__acrt_iob_func(1));
  v5 = dat_42c000;
  v6[0] = dat_42c008;
  if ((((((union { unsigned long long from; double to; }){ .from = ((union { double from; unsigned long long to; }){ .from = dat_42c010 + (dat_42c000 + dat_42c008) }).to & dat_42c020 }).to < dat_42c030) && (((union { unsigned long long from; double to; }){ .from = ((union { double from; unsigned long long to; }){ .from = dat_42c038 + (dat_42c000 - dat_42c008) }).to & dat_42c020 }).to < dat_42c030)) && (((union { unsigned long long from; double to; }){ .from = ((union { double from; unsigned long long to; }){ .from = dat_42c040 + dat_42c000 * dat_42c008 }).to & dat_42c020 }).to < dat_42c030)) && (((union { unsigned long long from; double to; }){ .from = ((union { double from; unsigned long long to; }){ .from = dat_42c048 + dat_42c000 / dat_42c008 }).to & dat_42c020 }).to < dat_42c030)) {
    v8 = 0;
    v9 = 1;
    s = "PASS";
  }
  else {
    sub_402120("  sum=%d diff=%d prod=%d quot=%d\n",(int)((dat_42c000 + dat_42c008) * dat_42c050),(int)((dat_42c000 - dat_42c008) * dat_42c050),(int)(dat_42c000 * dat_42c008 * dat_42c050),(int)((dat_42c000 / dat_42c008) * dat_42c058));
    v8 = 1;
    v9 = 0;
    s = "FAIL";
  }
  puts(s);
  sub_402120("2. Float arithmetic  ... ");
  fflush((void *)__acrt_iob_func(1));
  v5 = ((union { unsigned long long from; double to; }){ .from = CONCAT44(((unsigned int *)&v5)[1],0x3fc00000) }).to;
  v6[0] = ((union { unsigned long long from; double to; }){ .from = CONCAT44(((unsigned int *)&v6[0])[1],0x40200000) }).to;
  if ((((union { unsigned int from; float to; }){ .from = ((union { float from; unsigned int to; }){ .from = dat_42c060 + 4.0f }).to & dat_42c070 }).to < dat_42c080) && (((union { unsigned int from; float to; }){ .from = ((union { float from; unsigned int to; }){ .from = dat_42c084 + 3.75f }).to & dat_42c070 }).to < dat_42c080)) {
    puts("PASS");
    v9 += 1;
  }
  else {
    sub_402120("  sum=%d prod=%d\n",(int)(dat_42c088 * 4.0f),(int)(dat_42c088 * 3.75f));
    puts("FAIL");
    v8 += 1;
  }
  sub_402120("3. Int<->Float cvt   ... ");
  fflush((void *)__acrt_iob_func(1));
  v6[0] = ((union { unsigned long long from; double to; }){ .from = CONCAT44(((unsigned int *)&v6[0])[1],0x2a) }).to;
  v5 = dat_42c090;
  if ((int)dat_42c090 != -7) { // branch-flip
    sub_402120("  back=%d trunc=%d\n",0x2a,(int)dat_42c090);
    puts("FAIL");
    v8 += 1;
  }
  else {
    puts("PASS");
    v9 += 1;
  }
  sub_402120("4. Memcpy/memset     ... ");
  fflush((void *)__acrt_iob_func(1));
  v5 = ((union { unsigned long long from; double to; }){ .from = CONCAT44(dat_42c0a4,dat_42c0a0) }).to;
  v11 = dat_42c0a8;
  v12 = dat_42c0ac;
  v13 = dat_42c0b0;
  v14 = dat_42c0b4;
  v15 = dat_42c0b8;
  v16 = dat_42c0bc;
  v17 = dat_42c0c0;
  v18 = dat_42c0c4;
  v19 = dat_42c0c8;
  v20 = dat_42c0cc;
  v21 = dat_42c0d0;
  v22 = dat_42c0d4;
  v23 = dat_42c0d8;
  v24 = dat_42c0dc;
  v7 = dat_42c0e0;
  v25 = dat_42c0e4;
  v26 = dat_42c0e8;
  v27 = dat_42c0ec;
  v28 = dat_42c0f0;
  v29 = dat_42c0f4;
  v30 = dat_42c0f8;
  v31 = dat_42c0fc;
  v32 = dat_42c100;
  v33 = dat_42c104;
  v34 = dat_42c108;
  v35 = dat_42c10c;
  v36 = dat_42c110;
  v37 = dat_42c114;
  v38 = dat_42c118;
  v39 = dat_42c11c;
  sub_42acf0(v6,&v5,0x80);
  v5 = ((union { unsigned long long from; double to; }){ .from = CONCAT44(dat_42c124,dat_42c120) }).to;
  v11 = dat_42c128;
  v12 = dat_42c12c;
  v13 = dat_42c120;
  v14 = dat_42c124;
  v15 = dat_42c128;
  v16 = dat_42c12c;
  v17 = dat_42c120;
  v18 = dat_42c124;
  v19 = dat_42c128;
  v20 = dat_42c12c;
  v21 = dat_42c120;
  v22 = dat_42c124;
  v23 = dat_42c128;
  v24 = dat_42c12c;
  v3 = 0;
  do {
    v2 = (int)((char *)v6)[v3] ^ v3;
    if (v2 != 0x55) break;
    v10 = v3 != 0x7f;
    v3 += 1;
  } while (v10);
  v4 = -0x40;
  do {
    if (((((char *)&v7)[v4] != '\xaa') || (((char *)&v7)[v4 + 1] != '\xaa')) || ((((char *)&v7)[v4 + 2] != '\xaa' || (((char *)&v7)[v4 + 3] != '\xaa')))) goto label_4013d6;
    v4 += 4;
  } while (v4);
  if (v2 != 0x55) { // branch-flip
label_4013d6:
    puts("FAIL");
    v8 += 1;
  }
  else {
    puts("PASS");
    v9 += 1;
  }
  sub_402120("5. Float compare     ... ");
  fflush((void *)__acrt_iob_func(1));
  v5 = dat_42c130;
  v6[0] = dat_42c138;
  v40 = dat_42c130;
  if (((!(dat_42c130 < dat_42c138)) || (NAN(dat_42c130))) || (dat_42c138 < dat_42c130)) {
    puts("FAIL");
    v8 += 1;
  }
  else {
    puts("PASS");
    v9 += 1;
  }
  sub_402120("6. Precision convert ... ");
  fflush((void *)__acrt_iob_func(1));
  v6[0] = ((union { unsigned long long from; double to; }){ .from = CONCAT44(((unsigned int *)&v6[0])[1],0x3fc00000) }).to;
  v5 = dat_42c140;
  if ((((union { unsigned long long from; double to; }){ .from = ((union { double from; unsigned long long to; }){ .from = dat_42c148 + 1.5 }).to & dat_42c020 }).to < dat_42c030) && (((union { unsigned int from; float to; }){ .from = ((union { float from; unsigned int to; }){ .from = (float)dat_42c140 + dat_42c150 }).to & dat_42c070 }).to < dat_42c080)) {
    puts("PASS");
    v9 += 1;
  }
  else {
    puts("FAIL");
    v8 += 1;
  }
  sub_402120("\nResults: %d passed, %d failed\n",v9,v8);
  return v8 != 0;
}
