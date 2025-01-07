import CS from '../capstone';

const fromHexString = (hexString) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

  // prettier-ignore
  const buffer = fromHexString("000280D2")
  const disassembler = new CS.CAPSTONE(CS.ARCH_ARM64, CS.MODE_ARM);
  disassembler.option(CS.OPT_DETAIL, true);
  const insns = disassembler.disasm(buffer, 0x1000);
  console.log(Bun.inspect(insns[0].detail.arm64))
  disassembler.close();
