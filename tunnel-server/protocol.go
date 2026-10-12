package main

import (
 "crypto/subtle"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "strings"
)

const (
 version byte = 1
 authorized byte = 0x7f
 maxFrame = 1300
 maxToken = 32
)
var errInvalidFrame=errors.New("invalid tunnel frame")

func readFrame(reader io.Reader) ([]byte,error) {
 var header [2]byte
 if _,err:=io.ReadFull(reader,header[:]);err!=nil{return nil,err}
 length:=int(binary.BigEndian.Uint16(header[:]))
 if length>maxFrame{return nil,errInvalidFrame}
 if length==0{return []byte{},nil} // keepalive
 data:=make([]byte,length)
 _,err:=io.ReadFull(reader,data)
 if err!=nil{return nil,err}
 return data,nil
}
func writeFrame(w io.Writer,payload []byte) error {
 if len(payload)>maxFrame{return errInvalidFrame}
 var hdr [2]byte
 binary.BigEndian.PutUint16(hdr[:],uint16(len(payload)))
 if _,err:=w.Write(hdr[:]);err!=nil{return err}
 _,err:=w.Write(payload)
 return err
}
func validIPv4(p []byte,source,dest string) bool {
 if len(p)<20||p[0]>>4!=4{return false}
 ihl:=int(p[0]&0x0f)*4
 if ihl<20||ihl>len(p){return false}
 total:=int(binary.BigEndian.Uint16(p[2:4]))
 if total!=len(p){return false}
 // A single beta client is assigned 10.74.0.2.
 return true
}
func tokenFromEnv() ([]byte,error) {
 token:=strings.TrimSpace(os.Getenv("GHOSTFORGE_TUNNEL_TOKEN"))
 if len(token)!=64{return nil,errors.New("GHOSTFORGE_TUNNEL_TOKEN must be 64 hexadecimal characters")}
 value,err:=hex.DecodeString(token)
 if err!=nil||len(value)!=maxToken{return nil,errors.New("tunnel token must be 32 random bytes in hex")}
 return value,nil
}
func validToken(received,expected []byte) bool {
 return len(received)==32 && len(expected)==32 && subtle.ConstantTimeCompare(received,expected)==1
}
