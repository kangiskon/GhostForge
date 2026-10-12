//go:build linux
package main

import (
 "fmt"
 "os"
 "os/exec"
 "syscall"
 "unsafe"
)

const (
 tunSetIff = 0x400454ca // Linux TUNSETIFF on x86_64/arm64
 iffTun = 0x0001
 iffNoPi = 0x1000
)

func openTun(name string) (*os.File,error) {
 if len(name)==0||len(name)>15{return nil,fmt.Errorf("invalid TUN interface name")}
 f,err:=os.OpenFile("/dev/net/tun",os.O_RDWR,0)
 if err!=nil{return nil,fmt.Errorf("open /dev/net/tun: %w",err)}
 var request [40]byte
 copy(request[:16],[]byte(name))
 request[16]=byte((iffTun|iffNoPi)&0xff)
 request[17]=byte((iffTun|iffNoPi)>>8)
 _,_,errno:=syscall.Syscall(syscall.SYS_IOCTL,f.Fd(),tunSetIff,uintptr(unsafe.Pointer(&request[0])))
 if errno!=0 { f.Close();return nil,fmt.Errorf("TUNSETIFF failed: %w",errno)}
 for _,args:=range [][]string{
  {"addr","replace","10.74.0.1/30","dev",name},
  {"link","set","dev",name,"mtu","1300","up"},
 } {
  output,err:=exec.Command("ip",args...).CombinedOutput()
  if err!=nil{f.Close();return nil,fmt.Errorf("ip %v: %v: %s",args,err,output)}
 }
 return f,nil
}
