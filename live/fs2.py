import rlp, json, urllib.request, sys
from Crypto.Hash import keccak
from eth_keys import keys

RPC="http://127.0.0.1:8545"
def k256(b):
    h=keccak.new(digest_bits=256); h.update(b); return h.digest()
def be(x):
    if isinstance(x,(bytes,bytearray)): return bytes(x)
    if x==0: return b''
    return x.to_bytes((x.bit_length()+7)//8,'big')
def rpc(m,p):
    req={"jsonrpc":"2.0","method":m,"params":p,"id":1}
    r=urllib.request.urlopen(urllib.request.Request(RPC,json.dumps(req).encode(),{'content-type':'application/json'}))
    return json.load(r)

CHAIN=0x13e02
VER=bytes.fromhex("00000000000000000000000000000000cafe8403")
AUTH_PK=bytes.fromhex("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")  # anvil#1 -> 0x7099...

def enc_frame(f):
    mode,flags,target,limits,value,data=f
    return [be(mode),be(flags),bytes(target),[be(limits[0]),be(limits[1])],be(value),bytes(data)]

def build(nonce, frames, sig_priv, signer_field, max_prio, max_fee, scheme=1, sig_override=None):
    fr=[enc_frame(f) for f in frames]
    def body(sig):
        return [be(CHAIN),be(nonce),bytes(VER),fr,[[be(scheme),bytes(signer_field),b'',sig]],[be(max_prio),be(max_fee),b''],[]]
    digest=k256(b'\x06'+rlp.encode(body(b'')))
    if sig_override is not None:
        sig=sig_override
    else:
        s=keys.PrivateKey(sig_priv).sign_msg_hash(digest)
        sig=bytes([s.v])+s.r.to_bytes(32,'big')+s.s.to_bytes(32,'big')
    raw=b'\x06'+rlp.encode(body(sig))
    return '0x'+raw.hex(), digest.hex()

def frames_for(recipient, value, aid, pred, sib, vexec=80000):
    data=aid+pred+sib
    return [
        [1,3,b'',[vexec,0],0,data],          # VERIFY self (null target -> sender), APPROVE exec+payment
        [2,0,recipient,[60000,0],value,b''],  # SENDER value transfer
    ]

def send_and_report(label, raw):
    res=rpc("eth_sendRawTransaction",[raw])
    if 'error' in res:
        print(f"[{label}] REJECTED at mempool: {res['error']['message'][:130]}")
        return None
    h=res['result']
    import time; time.sleep(1.5)
    rc=rpc("eth_getTransactionReceipt",[h]).get('result')
    if rc is None:
        print(f"[{label}] accepted to pool but NOT mined (dropped/invalid): {h}")
        return None
    st=int(rc['status'],16)
    fr=rc.get('frameReceipts')
    print(f"[{label}] MINED block {int(rc['blockNumber'],16)} status {st} type {rc.get('type')}")
    if fr: print(f"          frameReceipts: {json.dumps(fr)[:300]}")
    return rc
