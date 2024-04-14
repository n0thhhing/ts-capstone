// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [m68k_const.py]
export const M68K_OPERAND_COUNT = 4;

export const M68K_REG_INVALID = 0;
export const M68K_REG_D0 = 1;
export const M68K_REG_D1 = 2;
export const M68K_REG_D2 = 3;
export const M68K_REG_D3 = 4;
export const M68K_REG_D4 = 5;
export const M68K_REG_D5 = 6;
export const M68K_REG_D6 = 7;
export const M68K_REG_D7 = 8;
export const M68K_REG_A0 = 9;
export const M68K_REG_A1 = 10;
export const M68K_REG_A2 = 11;
export const M68K_REG_A3 = 12;
export const M68K_REG_A4 = 13;
export const M68K_REG_A5 = 14;
export const M68K_REG_A6 = 15;
export const M68K_REG_A7 = 16;
export const M68K_REG_FP0 = 17;
export const M68K_REG_FP1 = 18;
export const M68K_REG_FP2 = 19;
export const M68K_REG_FP3 = 20;
export const M68K_REG_FP4 = 21;
export const M68K_REG_FP5 = 22;
export const M68K_REG_FP6 = 23;
export const M68K_REG_FP7 = 24;
export const M68K_REG_PC = 25;
export const M68K_REG_SR = 26;
export const M68K_REG_CCR = 27;
export const M68K_REG_SFC = 28;
export const M68K_REG_DFC = 29;
export const M68K_REG_USP = 30;
export const M68K_REG_VBR = 31;
export const M68K_REG_CACR = 32;
export const M68K_REG_CAAR = 33;
export const M68K_REG_MSP = 34;
export const M68K_REG_ISP = 35;
export const M68K_REG_TC = 36;
export const M68K_REG_ITT0 = 37;
export const M68K_REG_ITT1 = 38;
export const M68K_REG_DTT0 = 39;
export const M68K_REG_DTT1 = 40;
export const M68K_REG_MMUSR = 41;
export const M68K_REG_URP = 42;
export const M68K_REG_SRP = 43;
export const M68K_REG_FPCR = 44;
export const M68K_REG_FPSR = 45;
export const M68K_REG_FPIAR = 46;
export const M68K_REG_ENDING = 47;

export const M68K_AM_NONE = 0;
export const M68K_AM_REG_DIRECT_DATA = 1;
export const M68K_AM_REG_DIRECT_ADDR = 2;
export const M68K_AM_REGI_ADDR = 3;
export const M68K_AM_REGI_ADDR_POST_INC = 4;
export const M68K_AM_REGI_ADDR_PRE_DEC = 5;
export const M68K_AM_REGI_ADDR_DISP = 6;
export const M68K_AM_AREGI_INDEX_8_BIT_DISP = 7;
export const M68K_AM_AREGI_INDEX_BASE_DISP = 8;
export const M68K_AM_MEMI_POST_INDEX = 9;
export const M68K_AM_MEMI_PRE_INDEX = 10;
export const M68K_AM_PCI_DISP = 11;
export const M68K_AM_PCI_INDEX_8_BIT_DISP = 12;
export const M68K_AM_PCI_INDEX_BASE_DISP = 13;
export const M68K_AM_PC_MEMI_POST_INDEX = 14;
export const M68K_AM_PC_MEMI_PRE_INDEX = 15;
export const M68K_AM_ABSOLUTE_DATA_SHORT = 16;
export const M68K_AM_ABSOLUTE_DATA_LONG = 17;
export const M68K_AM_IMMEDIATE = 18;
export const M68K_AM_BRANCH_DISPLACEMENT = 19;

export const M68K_OP_INVALID = 0;
export const M68K_OP_REG = 1;
export const M68K_OP_IMM = 2;
export const M68K_OP_MEM = 3;
export const M68K_OP_FP_SINGLE = 4;
export const M68K_OP_FP_DOUBLE = 5;
export const M68K_OP_REG_BITS = 6;
export const M68K_OP_REG_PAIR = 7;
export const M68K_OP_BR_DISP = 8;

export const M68K_OP_BR_DISP_SIZE_INVALID = 0;
export const M68K_OP_BR_DISP_SIZE_BYTE = 1;
export const M68K_OP_BR_DISP_SIZE_WORD = 2;
export const M68K_OP_BR_DISP_SIZE_LONG = 4;

export const M68K_CPU_SIZE_NONE = 0;
export const M68K_CPU_SIZE_BYTE = 1;
export const M68K_CPU_SIZE_WORD = 2;
export const M68K_CPU_SIZE_LONG = 4;

export const M68K_FPU_SIZE_NONE = 0;
export const M68K_FPU_SIZE_SINGLE = 4;
export const M68K_FPU_SIZE_DOUBLE = 8;
export const M68K_FPU_SIZE_EXTENDED = 12;

export const M68K_SIZE_TYPE_INVALID = 0;
export const M68K_SIZE_TYPE_CPU = 1;
export const M68K_SIZE_TYPE_FPU = 2;

export const M68K_INS_INVALID = 0;
export const M68K_INS_ABCD = 1;
export const M68K_INS_ADD = 2;
export const M68K_INS_ADDA = 3;
export const M68K_INS_ADDI = 4;
export const M68K_INS_ADDQ = 5;
export const M68K_INS_ADDX = 6;
export const M68K_INS_AND = 7;
export const M68K_INS_ANDI = 8;
export const M68K_INS_ASL = 9;
export const M68K_INS_ASR = 10;
export const M68K_INS_BHS = 11;
export const M68K_INS_BLO = 12;
export const M68K_INS_BHI = 13;
export const M68K_INS_BLS = 14;
export const M68K_INS_BCC = 15;
export const M68K_INS_BCS = 16;
export const M68K_INS_BNE = 17;
export const M68K_INS_BEQ = 18;
export const M68K_INS_BVC = 19;
export const M68K_INS_BVS = 20;
export const M68K_INS_BPL = 21;
export const M68K_INS_BMI = 22;
export const M68K_INS_BGE = 23;
export const M68K_INS_BLT = 24;
export const M68K_INS_BGT = 25;
export const M68K_INS_BLE = 26;
export const M68K_INS_BRA = 27;
export const M68K_INS_BSR = 28;
export const M68K_INS_BCHG = 29;
export const M68K_INS_BCLR = 30;
export const M68K_INS_BSET = 31;
export const M68K_INS_BTST = 32;
export const M68K_INS_BFCHG = 33;
export const M68K_INS_BFCLR = 34;
export const M68K_INS_BFEXTS = 35;
export const M68K_INS_BFEXTU = 36;
export const M68K_INS_BFFFO = 37;
export const M68K_INS_BFINS = 38;
export const M68K_INS_BFSET = 39;
export const M68K_INS_BFTST = 40;
export const M68K_INS_BKPT = 41;
export const M68K_INS_CALLM = 42;
export const M68K_INS_CAS = 43;
export const M68K_INS_CAS2 = 44;
export const M68K_INS_CHK = 45;
export const M68K_INS_CHK2 = 46;
export const M68K_INS_CLR = 47;
export const M68K_INS_CMP = 48;
export const M68K_INS_CMPA = 49;
export const M68K_INS_CMPI = 50;
export const M68K_INS_CMPM = 51;
export const M68K_INS_CMP2 = 52;
export const M68K_INS_CINVL = 53;
export const M68K_INS_CINVP = 54;
export const M68K_INS_CINVA = 55;
export const M68K_INS_CPUSHL = 56;
export const M68K_INS_CPUSHP = 57;
export const M68K_INS_CPUSHA = 58;
export const M68K_INS_DBT = 59;
export const M68K_INS_DBF = 60;
export const M68K_INS_DBHI = 61;
export const M68K_INS_DBLS = 62;
export const M68K_INS_DBCC = 63;
export const M68K_INS_DBCS = 64;
export const M68K_INS_DBNE = 65;
export const M68K_INS_DBEQ = 66;
export const M68K_INS_DBVC = 67;
export const M68K_INS_DBVS = 68;
export const M68K_INS_DBPL = 69;
export const M68K_INS_DBMI = 70;
export const M68K_INS_DBGE = 71;
export const M68K_INS_DBLT = 72;
export const M68K_INS_DBGT = 73;
export const M68K_INS_DBLE = 74;
export const M68K_INS_DBRA = 75;
export const M68K_INS_DIVS = 76;
export const M68K_INS_DIVSL = 77;
export const M68K_INS_DIVU = 78;
export const M68K_INS_DIVUL = 79;
export const M68K_INS_EOR = 80;
export const M68K_INS_EORI = 81;
export const M68K_INS_EXG = 82;
export const M68K_INS_EXT = 83;
export const M68K_INS_EXTB = 84;
export const M68K_INS_FABS = 85;
export const M68K_INS_FSABS = 86;
export const M68K_INS_FDABS = 87;
export const M68K_INS_FACOS = 88;
export const M68K_INS_FADD = 89;
export const M68K_INS_FSADD = 90;
export const M68K_INS_FDADD = 91;
export const M68K_INS_FASIN = 92;
export const M68K_INS_FATAN = 93;
export const M68K_INS_FATANH = 94;
export const M68K_INS_FBF = 95;
export const M68K_INS_FBEQ = 96;
export const M68K_INS_FBOGT = 97;
export const M68K_INS_FBOGE = 98;
export const M68K_INS_FBOLT = 99;
export const M68K_INS_FBOLE = 100;
export const M68K_INS_FBOGL = 101;
export const M68K_INS_FBOR = 102;
export const M68K_INS_FBUN = 103;
export const M68K_INS_FBUEQ = 104;
export const M68K_INS_FBUGT = 105;
export const M68K_INS_FBUGE = 106;
export const M68K_INS_FBULT = 107;
export const M68K_INS_FBULE = 108;
export const M68K_INS_FBNE = 109;
export const M68K_INS_FBT = 110;
export const M68K_INS_FBSF = 111;
export const M68K_INS_FBSEQ = 112;
export const M68K_INS_FBGT = 113;
export const M68K_INS_FBGE = 114;
export const M68K_INS_FBLT = 115;
export const M68K_INS_FBLE = 116;
export const M68K_INS_FBGL = 117;
export const M68K_INS_FBGLE = 118;
export const M68K_INS_FBNGLE = 119;
export const M68K_INS_FBNGL = 120;
export const M68K_INS_FBNLE = 121;
export const M68K_INS_FBNLT = 122;
export const M68K_INS_FBNGE = 123;
export const M68K_INS_FBNGT = 124;
export const M68K_INS_FBSNE = 125;
export const M68K_INS_FBST = 126;
export const M68K_INS_FCMP = 127;
export const M68K_INS_FCOS = 128;
export const M68K_INS_FCOSH = 129;
export const M68K_INS_FDBF = 130;
export const M68K_INS_FDBEQ = 131;
export const M68K_INS_FDBOGT = 132;
export const M68K_INS_FDBOGE = 133;
export const M68K_INS_FDBOLT = 134;
export const M68K_INS_FDBOLE = 135;
export const M68K_INS_FDBOGL = 136;
export const M68K_INS_FDBOR = 137;
export const M68K_INS_FDBUN = 138;
export const M68K_INS_FDBUEQ = 139;
export const M68K_INS_FDBUGT = 140;
export const M68K_INS_FDBUGE = 141;
export const M68K_INS_FDBULT = 142;
export const M68K_INS_FDBULE = 143;
export const M68K_INS_FDBNE = 144;
export const M68K_INS_FDBT = 145;
export const M68K_INS_FDBSF = 146;
export const M68K_INS_FDBSEQ = 147;
export const M68K_INS_FDBGT = 148;
export const M68K_INS_FDBGE = 149;
export const M68K_INS_FDBLT = 150;
export const M68K_INS_FDBLE = 151;
export const M68K_INS_FDBGL = 152;
export const M68K_INS_FDBGLE = 153;
export const M68K_INS_FDBNGLE = 154;
export const M68K_INS_FDBNGL = 155;
export const M68K_INS_FDBNLE = 156;
export const M68K_INS_FDBNLT = 157;
export const M68K_INS_FDBNGE = 158;
export const M68K_INS_FDBNGT = 159;
export const M68K_INS_FDBSNE = 160;
export const M68K_INS_FDBST = 161;
export const M68K_INS_FDIV = 162;
export const M68K_INS_FSDIV = 163;
export const M68K_INS_FDDIV = 164;
export const M68K_INS_FETOX = 165;
export const M68K_INS_FETOXM1 = 166;
export const M68K_INS_FGETEXP = 167;
export const M68K_INS_FGETMAN = 168;
export const M68K_INS_FINT = 169;
export const M68K_INS_FINTRZ = 170;
export const M68K_INS_FLOG10 = 171;
export const M68K_INS_FLOG2 = 172;
export const M68K_INS_FLOGN = 173;
export const M68K_INS_FLOGNP1 = 174;
export const M68K_INS_FMOD = 175;
export const M68K_INS_FMOVE = 176;
export const M68K_INS_FSMOVE = 177;
export const M68K_INS_FDMOVE = 178;
export const M68K_INS_FMOVECR = 179;
export const M68K_INS_FMOVEM = 180;
export const M68K_INS_FMUL = 181;
export const M68K_INS_FSMUL = 182;
export const M68K_INS_FDMUL = 183;
export const M68K_INS_FNEG = 184;
export const M68K_INS_FSNEG = 185;
export const M68K_INS_FDNEG = 186;
export const M68K_INS_FNOP = 187;
export const M68K_INS_FREM = 188;
export const M68K_INS_FRESTORE = 189;
export const M68K_INS_FSAVE = 190;
export const M68K_INS_FSCALE = 191;
export const M68K_INS_FSGLDIV = 192;
export const M68K_INS_FSGLMUL = 193;
export const M68K_INS_FSIN = 194;
export const M68K_INS_FSINCOS = 195;
export const M68K_INS_FSINH = 196;
export const M68K_INS_FSQRT = 197;
export const M68K_INS_FSSQRT = 198;
export const M68K_INS_FDSQRT = 199;
export const M68K_INS_FSF = 200;
export const M68K_INS_FSBEQ = 201;
export const M68K_INS_FSOGT = 202;
export const M68K_INS_FSOGE = 203;
export const M68K_INS_FSOLT = 204;
export const M68K_INS_FSOLE = 205;
export const M68K_INS_FSOGL = 206;
export const M68K_INS_FSOR = 207;
export const M68K_INS_FSUN = 208;
export const M68K_INS_FSUEQ = 209;
export const M68K_INS_FSUGT = 210;
export const M68K_INS_FSUGE = 211;
export const M68K_INS_FSULT = 212;
export const M68K_INS_FSULE = 213;
export const M68K_INS_FSNE = 214;
export const M68K_INS_FST = 215;
export const M68K_INS_FSSF = 216;
export const M68K_INS_FSSEQ = 217;
export const M68K_INS_FSGT = 218;
export const M68K_INS_FSGE = 219;
export const M68K_INS_FSLT = 220;
export const M68K_INS_FSLE = 221;
export const M68K_INS_FSGL = 222;
export const M68K_INS_FSGLE = 223;
export const M68K_INS_FSNGLE = 224;
export const M68K_INS_FSNGL = 225;
export const M68K_INS_FSNLE = 226;
export const M68K_INS_FSNLT = 227;
export const M68K_INS_FSNGE = 228;
export const M68K_INS_FSNGT = 229;
export const M68K_INS_FSSNE = 230;
export const M68K_INS_FSST = 231;
export const M68K_INS_FSUB = 232;
export const M68K_INS_FSSUB = 233;
export const M68K_INS_FDSUB = 234;
export const M68K_INS_FTAN = 235;
export const M68K_INS_FTANH = 236;
export const M68K_INS_FTENTOX = 237;
export const M68K_INS_FTRAPF = 238;
export const M68K_INS_FTRAPEQ = 239;
export const M68K_INS_FTRAPOGT = 240;
export const M68K_INS_FTRAPOGE = 241;
export const M68K_INS_FTRAPOLT = 242;
export const M68K_INS_FTRAPOLE = 243;
export const M68K_INS_FTRAPOGL = 244;
export const M68K_INS_FTRAPOR = 245;
export const M68K_INS_FTRAPUN = 246;
export const M68K_INS_FTRAPUEQ = 247;
export const M68K_INS_FTRAPUGT = 248;
export const M68K_INS_FTRAPUGE = 249;
export const M68K_INS_FTRAPULT = 250;
export const M68K_INS_FTRAPULE = 251;
export const M68K_INS_FTRAPNE = 252;
export const M68K_INS_FTRAPT = 253;
export const M68K_INS_FTRAPSF = 254;
export const M68K_INS_FTRAPSEQ = 255;
export const M68K_INS_FTRAPGT = 256;
export const M68K_INS_FTRAPGE = 257;
export const M68K_INS_FTRAPLT = 258;
export const M68K_INS_FTRAPLE = 259;
export const M68K_INS_FTRAPGL = 260;
export const M68K_INS_FTRAPGLE = 261;
export const M68K_INS_FTRAPNGLE = 262;
export const M68K_INS_FTRAPNGL = 263;
export const M68K_INS_FTRAPNLE = 264;
export const M68K_INS_FTRAPNLT = 265;
export const M68K_INS_FTRAPNGE = 266;
export const M68K_INS_FTRAPNGT = 267;
export const M68K_INS_FTRAPSNE = 268;
export const M68K_INS_FTRAPST = 269;
export const M68K_INS_FTST = 270;
export const M68K_INS_FTWOTOX = 271;
export const M68K_INS_HALT = 272;
export const M68K_INS_ILLEGAL = 273;
export const M68K_INS_JMP = 274;
export const M68K_INS_JSR = 275;
export const M68K_INS_LEA = 276;
export const M68K_INS_LINK = 277;
export const M68K_INS_LPSTOP = 278;
export const M68K_INS_LSL = 279;
export const M68K_INS_LSR = 280;
export const M68K_INS_MOVE = 281;
export const M68K_INS_MOVEA = 282;
export const M68K_INS_MOVEC = 283;
export const M68K_INS_MOVEM = 284;
export const M68K_INS_MOVEP = 285;
export const M68K_INS_MOVEQ = 286;
export const M68K_INS_MOVES = 287;
export const M68K_INS_MOVE16 = 288;
export const M68K_INS_MULS = 289;
export const M68K_INS_MULU = 290;
export const M68K_INS_NBCD = 291;
export const M68K_INS_NEG = 292;
export const M68K_INS_NEGX = 293;
export const M68K_INS_NOP = 294;
export const M68K_INS_NOT = 295;
export const M68K_INS_OR = 296;
export const M68K_INS_ORI = 297;
export const M68K_INS_PACK = 298;
export const M68K_INS_PEA = 299;
export const M68K_INS_PFLUSH = 300;
export const M68K_INS_PFLUSHA = 301;
export const M68K_INS_PFLUSHAN = 302;
export const M68K_INS_PFLUSHN = 303;
export const M68K_INS_PLOADR = 304;
export const M68K_INS_PLOADW = 305;
export const M68K_INS_PLPAR = 306;
export const M68K_INS_PLPAW = 307;
export const M68K_INS_PMOVE = 308;
export const M68K_INS_PMOVEFD = 309;
export const M68K_INS_PTESTR = 310;
export const M68K_INS_PTESTW = 311;
export const M68K_INS_PULSE = 312;
export const M68K_INS_REMS = 313;
export const M68K_INS_REMU = 314;
export const M68K_INS_RESET = 315;
export const M68K_INS_ROL = 316;
export const M68K_INS_ROR = 317;
export const M68K_INS_ROXL = 318;
export const M68K_INS_ROXR = 319;
export const M68K_INS_RTD = 320;
export const M68K_INS_RTE = 321;
export const M68K_INS_RTM = 322;
export const M68K_INS_RTR = 323;
export const M68K_INS_RTS = 324;
export const M68K_INS_SBCD = 325;
export const M68K_INS_ST = 326;
export const M68K_INS_SF = 327;
export const M68K_INS_SHI = 328;
export const M68K_INS_SLS = 329;
export const M68K_INS_SCC = 330;
export const M68K_INS_SHS = 331;
export const M68K_INS_SCS = 332;
export const M68K_INS_SLO = 333;
export const M68K_INS_SNE = 334;
export const M68K_INS_SEQ = 335;
export const M68K_INS_SVC = 336;
export const M68K_INS_SVS = 337;
export const M68K_INS_SPL = 338;
export const M68K_INS_SMI = 339;
export const M68K_INS_SGE = 340;
export const M68K_INS_SLT = 341;
export const M68K_INS_SGT = 342;
export const M68K_INS_SLE = 343;
export const M68K_INS_STOP = 344;
export const M68K_INS_SUB = 345;
export const M68K_INS_SUBA = 346;
export const M68K_INS_SUBI = 347;
export const M68K_INS_SUBQ = 348;
export const M68K_INS_SUBX = 349;
export const M68K_INS_SWAP = 350;
export const M68K_INS_TAS = 351;
export const M68K_INS_TRAP = 352;
export const M68K_INS_TRAPV = 353;
export const M68K_INS_TRAPT = 354;
export const M68K_INS_TRAPF = 355;
export const M68K_INS_TRAPHI = 356;
export const M68K_INS_TRAPLS = 357;
export const M68K_INS_TRAPCC = 358;
export const M68K_INS_TRAPHS = 359;
export const M68K_INS_TRAPCS = 360;
export const M68K_INS_TRAPLO = 361;
export const M68K_INS_TRAPNE = 362;
export const M68K_INS_TRAPEQ = 363;
export const M68K_INS_TRAPVC = 364;
export const M68K_INS_TRAPVS = 365;
export const M68K_INS_TRAPPL = 366;
export const M68K_INS_TRAPMI = 367;
export const M68K_INS_TRAPGE = 368;
export const M68K_INS_TRAPLT = 369;
export const M68K_INS_TRAPGT = 370;
export const M68K_INS_TRAPLE = 371;
export const M68K_INS_TST = 372;
export const M68K_INS_UNLK = 373;
export const M68K_INS_UNPK = 374;
export const M68K_INS_ENDING = 375;

export const M68K_GRP_INVALID = 0;
export const M68K_GRP_JUMP = 1;
export const M68K_GRP_RET = 3;
export const M68K_GRP_IRET = 5;
export const M68K_GRP_BRANCH_RELATIVE = 7;
export const M68K_GRP_ENDING = 8;