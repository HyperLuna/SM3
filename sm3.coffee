crypt=require('crypt')

ROL=crypt.rotl
B2W=crypt.bytesToWords

IV=[0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e]

T0=0x79cc4519
T1=0x7a879d8a

XOR=(X,Y,Z)->
  X^Y^Z

FF1=(X,Y,Z)->
  (X&Y)|(X&Z)|(Y&Z)

GG1=(X,Y,Z)->
  (X&Y)|(~X&Z)

P0=(X)->
  X^ROL(X,9)^ROL(X,17)

P1=(X)->
  X^ROL(X,15)^ROL(X,23)

CF=(V,B)->
  [a,b,c,d,e,f,g,h]=V
  _CF=(i,t,ff,gg)->
    ss1=ROL(ROL(a,12)+e+ROL(t,i),7)
    ss2=ss1^ROL(a,12)
    tt1=ff(a,b,c)+d+ss2+B.wq[i]
    tt2=gg(e,f,g)+h+ss1+B.ws[i]
    [d,c,b,a,h,g,f,e]=[c,ROL(b,9),a,tt1,g,ROL(f,19),e,P0(tt2)]
  for i in [0...16]
    _CF(i,T0,XOR,XOR)
  for i in [16...64]
    _CF(i,T1,FF1,GG1)

  v=[a,b,c,d,e,f,g,h]
  v[i]^V[i] for i in [0...8]

_SM3=(msg)->
  len=msg.length
  msg.push 128
  msg=B2W(msg)
  msg.push (0 for i in [msg.length%16...(if msg.length%16>14 then 30 else 14)])...
  msg.push len>>>29,len<<3 #JS not support 64 bit integer

  bs=[]
  for i in [0...msg.length] by 16
    ws=msg[i...i+16]
    for i in [16...68]
      ws[i]=P1(ws[i-16]^ws[i-9]^ROL(ws[i-3],15))^ROL(ws[i-13],7)^ws[i-6]
    wq=(ws[i]^ws[i+4] for i in [0...64])
    bs.push {ws:ws,wq:wq}

  v=IV
  for b in bs
    v=CF(v,b)

  return v

module.exports=(msg)->
  v=_SM3(msg.charCodeAt(i) for i in [0...msg.length])
  h=((i>>>0).toString 16 for i in v)
  hash=""
  for i in [0...h.length]
    while h[i].length<8
      hash+="0"
    hash+=h[i]
    hash+=" "
  
  return hash



