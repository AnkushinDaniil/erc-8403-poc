object "Verifier" {
  code {
    let root := 0
    let argStart := sub(codesize(), 32)
    codecopy(0, argStart, 32)
    root := mload(0)
    sstore(0, root)
    datacopy(0, dataoffset("runtime"), datasize("runtime"))
    return(0, datasize("runtime"))
  }
  object "runtime" {
    code {
      let fidx := verbatim_1i_1o(hex"b0", 0x0a)
      let aid  := verbatim_2i_1o(hex"b1", 0, fidx)
      let pred := verbatim_2i_1o(hex"b1", 32, fidx)
      let sib  := verbatim_2i_1o(hex"b1", 64, fidx)
      let signer := verbatim_2i_1o(hex"b4", 0, 0x00)
      if iszero(eq(signer, pred)) { revert(0, 0) }
      mstore(0, aid)
      mstore(32, pred)
      let leaf := keccak256(0, 64)
      let root := sload(0)
      let computed := leaf
      if iszero(iszero(sib)) {
        switch lt(leaf, sib)
        case 1 { mstore(0, leaf) mstore(32, sib) }
        default { mstore(0, sib) mstore(32, leaf) }
        computed := keccak256(0, 64)
      }
      if iszero(eq(computed, root)) { revert(0, 0) }
      verbatim_3i_0o(hex"aa", 0, 0, 3)
      stop()
    }
  }
}
