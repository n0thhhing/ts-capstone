/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM

enum {
  AArch64_FeatureAES = 0,
  AArch64_FeatureAM = 1,
  AArch64_FeatureAMVS = 2,
  AArch64_FeatureAggressiveFMA = 3,
  AArch64_FeatureAll = 4,
  AArch64_FeatureAltFPCmp = 5,
  AArch64_FeatureAlternateSExtLoadCVTF32Pattern = 6,
  AArch64_FeatureAppleA7SysReg = 7,
  AArch64_FeatureArithmeticBccFusion = 8,
  AArch64_FeatureArithmeticCbzFusion = 9,
  AArch64_FeatureAscendStoreAddress = 10,
  AArch64_FeatureB16B16 = 11,
  AArch64_FeatureBF16 = 12,
  AArch64_FeatureBRBE = 13,
  AArch64_FeatureBalanceFPOps = 14,
  AArch64_FeatureBranchTargetId = 15,
  AArch64_FeatureCCIDX = 16,
  AArch64_FeatureCCPP = 17,
  AArch64_FeatureCLRBHB = 18,
  AArch64_FeatureCONTEXTIDREL2 = 19,
  AArch64_FeatureCRC = 20,
  AArch64_FeatureCSSC = 21,
  AArch64_FeatureCacheDeepPersist = 22,
  AArch64_FeatureCallSavedX8 = 23,
  AArch64_FeatureCallSavedX9 = 24,
  AArch64_FeatureCallSavedX10 = 25,
  AArch64_FeatureCallSavedX11 = 26,
  AArch64_FeatureCallSavedX12 = 27,
  AArch64_FeatureCallSavedX13 = 28,
  AArch64_FeatureCallSavedX14 = 29,
  AArch64_FeatureCallSavedX15 = 30,
  AArch64_FeatureCallSavedX18 = 31,
  AArch64_FeatureCmpBccFusion = 32,
  AArch64_FeatureComplxNum = 33,
  AArch64_FeatureCrypto = 34,
  AArch64_FeatureCustomCheapAsMoveHandling = 35,
  AArch64_FeatureD128 = 36,
  AArch64_FeatureDIT = 37,
  AArch64_FeatureDisableLatencySchedHeuristic = 38,
  AArch64_FeatureDotProd = 39,
  AArch64_FeatureEL2VMSA = 40,
  AArch64_FeatureEL3 = 41,
  AArch64_FeatureETE = 42,
  AArch64_FeatureEnableSelectOptimize = 43,
  AArch64_FeatureEnhancedCounterVirtualization = 44,
  AArch64_FeatureExperimentalZeroingPseudos = 45,
  AArch64_FeatureExynosCheapAsMoveHandling = 46,
  AArch64_FeatureFMV = 47,
  AArch64_FeatureFP16FML = 48,
  AArch64_FeatureFPARMv8 = 49,
  AArch64_FeatureFRInt3264 = 50,
  AArch64_FeatureFineGrainedTraps = 51,
  AArch64_FeatureFixCortexA53_835769 = 52,
  AArch64_FeatureFlagM = 53,
  AArch64_FeatureForce32BitJumpTables = 54,
  AArch64_FeatureFullFP16 = 55,
  AArch64_FeatureFuseAES = 56,
  AArch64_FeatureFuseAddress = 57,
  AArch64_FeatureFuseAdrpAdd = 58,
  AArch64_FeatureFuseArithmeticLogic = 59,
  AArch64_FeatureFuseCCSelect = 60,
  AArch64_FeatureFuseCryptoEOR = 61,
  AArch64_FeatureFuseLiterals = 62,
  AArch64_FeatureHBC = 63,
  AArch64_FeatureHCX = 64,
  AArch64_FeatureHardenSlsBlr = 65,
  AArch64_FeatureHardenSlsNoComdat = 66,
  AArch64_FeatureHardenSlsRetBr = 67,
  AArch64_FeatureITE = 68,
  AArch64_FeatureJS = 69,
  AArch64_FeatureLOR = 70,
  AArch64_FeatureLS64 = 71,
  AArch64_FeatureLSE = 72,
  AArch64_FeatureLSE2 = 73,
  AArch64_FeatureLSE128 = 74,
  AArch64_FeatureLSLFast = 75,
  AArch64_FeatureMEC = 76,
  AArch64_FeatureMOPS = 77,
  AArch64_FeatureMPAM = 78,
  AArch64_FeatureMTE = 79,
  AArch64_FeatureMatMulFP32 = 80,
  AArch64_FeatureMatMulFP64 = 81,
  AArch64_FeatureMatMulInt8 = 82,
  AArch64_FeatureNEON = 83,
  AArch64_FeatureNMI = 84,
  AArch64_FeatureNV = 85,
  AArch64_FeatureNoBTIAtReturnTwice = 86,
  AArch64_FeatureNoNegativeImmediates = 87,
  AArch64_FeatureNoZCZeroingFP = 88,
  AArch64_FeatureOutlineAtomics = 89,
  AArch64_FeaturePAN = 90,
  AArch64_FeaturePAN_RWV = 91,
  AArch64_FeaturePAuth = 92,
  AArch64_FeaturePRFM_SLC = 93,
  AArch64_FeaturePerfMon = 94,
  AArch64_FeaturePostRAScheduler = 95,
  AArch64_FeaturePredRes = 96,
  AArch64_FeaturePredictableSelectIsExpensive = 97,
  AArch64_FeaturePsUAO = 98,
  AArch64_FeatureRAS = 99,
  AArch64_FeatureRASv2 = 100,
  AArch64_FeatureRCPC = 101,
  AArch64_FeatureRCPC3 = 102,
  AArch64_FeatureRCPC_IMMO = 103,
  AArch64_FeatureRDM = 104,
  AArch64_FeatureRME = 105,
  AArch64_FeatureRandGen = 106,
  AArch64_FeatureReserveX1 = 107,
  AArch64_FeatureReserveX2 = 108,
  AArch64_FeatureReserveX3 = 109,
  AArch64_FeatureReserveX4 = 110,
  AArch64_FeatureReserveX5 = 111,
  AArch64_FeatureReserveX6 = 112,
  AArch64_FeatureReserveX7 = 113,
  AArch64_FeatureReserveX9 = 114,
  AArch64_FeatureReserveX10 = 115,
  AArch64_FeatureReserveX11 = 116,
  AArch64_FeatureReserveX12 = 117,
  AArch64_FeatureReserveX13 = 118,
  AArch64_FeatureReserveX14 = 119,
  AArch64_FeatureReserveX15 = 120,
  AArch64_FeatureReserveX18 = 121,
  AArch64_FeatureReserveX20 = 122,
  AArch64_FeatureReserveX21 = 123,
  AArch64_FeatureReserveX22 = 124,
  AArch64_FeatureReserveX23 = 125,
  AArch64_FeatureReserveX24 = 126,
  AArch64_FeatureReserveX25 = 127,
  AArch64_FeatureReserveX26 = 128,
  AArch64_FeatureReserveX27 = 129,
  AArch64_FeatureReserveX28 = 130,
  AArch64_FeatureReserveX30 = 131,
  AArch64_FeatureSB = 132,
  AArch64_FeatureSEL2 = 133,
  AArch64_FeatureSHA2 = 134,
  AArch64_FeatureSHA3 = 135,
  AArch64_FeatureSM4 = 136,
  AArch64_FeatureSME = 137,
  AArch64_FeatureSME2 = 138,
  AArch64_FeatureSME2p1 = 139,
  AArch64_FeatureSMEF16F16 = 140,
  AArch64_FeatureSMEF64F64 = 141,
  AArch64_FeatureSMEI16I64 = 142,
  AArch64_FeatureSPE = 143,
  AArch64_FeatureSPECRES2 = 144,
  AArch64_FeatureSPE_EEF = 145,
  AArch64_FeatureSSBS = 146,
  AArch64_FeatureSVE = 147,
  AArch64_FeatureSVE2 = 148,
  AArch64_FeatureSVE2AES = 149,
  AArch64_FeatureSVE2BitPerm = 150,
  AArch64_FeatureSVE2SHA3 = 151,
  AArch64_FeatureSVE2SM4 = 152,
  AArch64_FeatureSVE2p1 = 153,
  AArch64_FeatureSlowMisaligned128Store = 154,
  AArch64_FeatureSlowPaired128 = 155,
  AArch64_FeatureSlowSTRQro = 156,
  AArch64_FeatureSpecRestrict = 157,
  AArch64_FeatureStrictAlign = 158,
  AArch64_FeatureTHE = 159,
  AArch64_FeatureTLB_RMI = 160,
  AArch64_FeatureTME = 161,
  AArch64_FeatureTRACEV8_4 = 162,
  AArch64_FeatureTRBE = 163,
  AArch64_FeatureTaggedGlobals = 164,
  AArch64_FeatureUseEL1ForTP = 165,
  AArch64_FeatureUseEL2ForTP = 166,
  AArch64_FeatureUseEL3ForTP = 167,
  AArch64_FeatureUseRSqrt = 168,
  AArch64_FeatureUseScalarIncVL = 169,
  AArch64_FeatureVH = 170,
  AArch64_FeatureWFxT = 171,
  AArch64_FeatureXS = 172,
  AArch64_FeatureZCRegMove = 173,
  AArch64_FeatureZCZeroing = 174,
  AArch64_FeatureZCZeroingFPWorkaround = 175,
  AArch64_FeatureZCZeroingGP = 176,
  AArch64_HasV8_0aOps = 177,
  AArch64_HasV8_0rOps = 178,
  AArch64_HasV8_1aOps = 179,
  AArch64_HasV8_2aOps = 180,
  AArch64_HasV8_3aOps = 181,
  AArch64_HasV8_4aOps = 182,
  AArch64_HasV8_5aOps = 183,
  AArch64_HasV8_6aOps = 184,
  AArch64_HasV8_7aOps = 185,
  AArch64_HasV8_8aOps = 186,
  AArch64_HasV8_9aOps = 187,
  AArch64_HasV9_0aOps = 188,
  AArch64_HasV9_1aOps = 189,
  AArch64_HasV9_2aOps = 190,
  AArch64_HasV9_3aOps = 191,
  AArch64_HasV9_4aOps = 192,
  AArch64_TuneA35 = 193,
  AArch64_TuneA53 = 194,
  AArch64_TuneA55 = 195,
  AArch64_TuneA57 = 196,
  AArch64_TuneA64FX = 197,
  AArch64_TuneA65 = 198,
  AArch64_TuneA72 = 199,
  AArch64_TuneA73 = 200,
  AArch64_TuneA75 = 201,
  AArch64_TuneA76 = 202,
  AArch64_TuneA77 = 203,
  AArch64_TuneA78 = 204,
  AArch64_TuneA78C = 205,
  AArch64_TuneA510 = 206,
  AArch64_TuneA710 = 207,
  AArch64_TuneA715 = 208,
  AArch64_TuneAmpere1 = 209,
  AArch64_TuneAmpere1A = 210,
  AArch64_TuneAppleA7 = 211,
  AArch64_TuneAppleA10 = 212,
  AArch64_TuneAppleA11 = 213,
  AArch64_TuneAppleA12 = 214,
  AArch64_TuneAppleA13 = 215,
  AArch64_TuneAppleA14 = 216,
  AArch64_TuneAppleA15 = 217,
  AArch64_TuneAppleA16 = 218,
  AArch64_TuneCarmel = 219,
  AArch64_TuneExynosM3 = 220,
  AArch64_TuneExynosM4 = 221,
  AArch64_TuneFalkor = 222,
  AArch64_TuneKryo = 223,
  AArch64_TuneNeoverse512TVB = 224,
  AArch64_TuneNeoverseE1 = 225,
  AArch64_TuneNeoverseN1 = 226,
  AArch64_TuneNeoverseN2 = 227,
  AArch64_TuneNeoverseV1 = 228,
  AArch64_TuneNeoverseV2 = 229,
  AArch64_TuneR82 = 230,
  AArch64_TuneSaphira = 231,
  AArch64_TuneTSV110 = 232,
  AArch64_TuneThunderX = 233,
  AArch64_TuneThunderX2T99 = 234,
  AArch64_TuneThunderX3T110 = 235,
  AArch64_TuneThunderXT81 = 236,
  AArch64_TuneThunderXT83 = 237,
  AArch64_TuneThunderXT88 = 238,
  AArch64_TuneX1 = 239,
  AArch64_TuneX2 = 240,
  AArch64_TuneX3 = 241,
  AArch64_NumSubtargetFeatures = 242
};
#endif // GET_SUBTARGETINFO_ENUM


