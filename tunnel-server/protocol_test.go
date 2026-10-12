package main

import (
 "bytes"
 "encoding/binary"
 "errors"
 "io"
 "os"
 "strings"
 "testing"
)
func TestFrameRoundTrip(t *testing.T){
 frames:=[][]byte{{},{0x45,0x00,0x00,0x14},bytes.Repeat([]byte{0x42},maxFrame)}
 for _,p:=range frames{
  var buf bytes.Buffer
  if err:=writeFrame(&buf,p);err!=nil{t.Fatal(err)}
  actual,err:=readFrame(&buf)
  if err!=nil{t.Fatal(err)}
  if !bytes.Equal(actual,p){t.Fatalf("expected %v bytes got %v",len(p),len(actual))}
 }
}
func TestFrameOversizeRejected(t *testing.T){
 var b bytes.Buffer
 binary.Write(&b,binary.BigEndian,uint16(maxFrame+1))
 if _,err:=readFrame(&b);!errors.Is(err,errInvalidFrame){t.Fatalf("unexpected: %v",err)}
 if err:=writeFrame(io.Discard,make([]byte,maxFrame+1));!errors.Is(err,errInvalidFrame){t.Fatal(err)}
}
func TestTruncatedFrameRejected(t *testing.T){
 b:=[]byte{0x00,0x06,0x45}
 if _,err:=readFrame(bytes.NewReader(b));!errors.Is(err,io.ErrUnexpectedEOF){t.Fatalf("unexpected %v",err)}
}
func TestTokenVerification(t *testing.T){
 key:=bytes.Repeat([]byte{0x41},32)
 if !validToken(key,append([]byte(nil),key...)){t.Fatal("valid token rejected")}
 bad:=append([]byte(nil),key...)
 bad[0]^=1
 if validToken(bad,key){t.Fatal("wrong token accepted")}
 if validToken(key[:4],key){t.Fatal("short token accepted")}
}
func TestTokenEnvMissingOrMalformed(t *testing.T){
 old:=os.Getenv("GHOSTFORGE_TUNNEL_TOKEN")
 t.Cleanup(func(){os.Setenv("GHOSTFORGE_TUNNEL_TOKEN",old)})
 os.Setenv("GHOSTFORGE_TUNNEL_TOKEN","12345")
 if _,err:=tokenFromEnv();err==nil{t.Fatal("weak token accepted")}
 os.Setenv("GHOSTFORGE_TUNNEL_TOKEN",strings.Repeat("a1",32))
 if b,err:=tokenFromEnv();err!=nil||len(b)!=32{t.Fatalf("unexpected %v",err)}
}
func TestIPv4SourceAndDestination(t *testing.T){
 p:=make([]byte,20)
 p[0]=0x45
 binary.BigEndian.PutUint16(p[2:4],20)
 copy(p[12:16],[]byte{10,74,0,2})
 copy(p[16:20],[]byte{1,1,1,2})
 if !validIPv4(p,"src",""){t.Fatal("valid packet rejected")}
 if validIPv4(p,"","dst"){t.Fatal("unwanted destination accepted")}
 p[12]=192
 if validIPv4(p,"src",""){t.Fatal("spoofed source accepted")}
}
