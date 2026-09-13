import rlp, sys, json, urllib.request
from Crypto.Hash import keccak
from eth_keys import keys

RPC="http://127.0.0.1:8600"
def k256(b):
    h=keccak.new(digest_bits=256); h.update(b); return h.digest()
def be(x):
    if isinstance(x,(bytes,bytearray)): return bytes(x)
    if x==0: return b''
    return x.to_bytes((x.bit_length()+7)//8,'big')
def rpc(method,params):
    req={"jsonrpc":"2.0","method":method,"params":params,"id":1}
    r=urllib.request.urlopen(urllib.request.Request(RPC,json.dumps(req).encode(),{'content-type':'application/json'}))
    return json.load(r)

def build(chain_id, nonce, sender, frames, priv, max_prio, max_fee):
    # frame: [mode, flags, target(20b), [execLimit, stateLimit], value, data]
    def enc_frame(f):
        mode,flags,target,limits,value,data=f
        return [be(mode),be(flags),bytes(target),[be(limits[0]),be(limits[1])],be(value),bytes(data)]
    fr=[enc_frame(f) for f in frames]
    # one signature over the canonical sig hash: [scheme=1, signer=b''(->sender), msg=b'', sig]
    def tx_body(sig):
        return [be(chain_id),be(nonce),bytes(sender),fr,[[be(1),b'',b'',sig]],[be(max_prio),be(max_fee),b''],[]]
    unsigned=tx_body(b'')                       # empty sig for the digest
    digest=k256(b'\x06'+rlp.encode(unsigned))   # compute_sig_hash
    sk=keys.PrivateKey(priv)
    s=sk.sign_msg_hash(digest)                  # canonical low-s; v in {0,1}
    sig=bytes([s.v])+s.r.to_bytes(32,'big')+s.s.to_bytes(32,'big')
    raw=b'\x06'+rlp.encode(tx_body(sig))
    return '0x'+raw.hex(), digest.hex()

if __name__=="__main__":
    priv=bytes.fromhex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
    sender=keys.PrivateKey(priv).public_key.to_canonical_address()
    recipient=bytes.fromhex("00000000000000000000000000000000000b0b01")  # existing acct (avoid state gas)
    chain_id=0x13e02
    nonce=int(rpc("eth_getTransactionCount",['0x'+sender.hex(),'latest'])['result'],16)
    bf=int(rpc("eth_getBlockByNumber",['latest',False])['result']['baseFeePerGas'],16)
    frames=[
        [1,3,sender,[80000,0],0,b''],                 # VERIFY self, APPROVE exec+payment
        [2,0,recipient,[60000,0],10**16,b''],         # SENDER value 0.01 ETH
    ]
    raw,dg=build(chain_id,nonce,sender,frames,priv,1_000_000_000,bf*2+2_000_000_000)
    print("sender 0x"+sender.hex(),"nonce",nonce,"digest",dg[:16])
    print("raw len",len(raw)//2)
    res=rpc("eth_sendRawTransaction",[raw])
    print("SEND:",json.dumps(res))
