import CS from '../capstone';

function fromHexString(hexString: string): Uint8Array {
  const match = hexString.match(/.{1,2}/g);
  return Uint8Array.from((match || []).map((byte: string) => parseInt(byte, 16)));
}

  // prettier-ignore
  const buffer = fromHexString("000280D2")

  const disassembler = new CS.CAPSTONE(CS.ARCH_ARM64, CS.MODE_ARM);
  disassembler.option(CS.OPT_DETAIL, true);
  const insns = disassembler.disasm(buffer, 0x1000);
  if (insns[0] && insns[0].detail) console.log(Bun.inspect(insns[0].detail.arm64))
  disassembler.close();
