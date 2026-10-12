//go:build linux
// GhostForge Tunnel v0.1. Experimental, single-client IPv4 tunnel over TLS 1.3/TCP.
// No custom cryptographic algorithms. No traffic payload logging.
package main

import (
 "crypto/tls"
 "errors"
 "flag"
 "io"
 "log"
 "net"
 "os"
 "sync"
 "time"
)

type gateway struct {
 tun *os.File
 secret []byte
 mu sync.RWMutex
 active *session
}
type session struct {
 conn net.Conn
 outbound chan []byte
 done chan struct{}
 once sync.Once
}
func (s *session) close() {
 s.once.Do(func(){close(s.done);_ = s.conn.Close()})
}
func (g *gateway) tunReader(){
 buf:=make([]byte,65535)
 for {
  n,err:=g.tun.Read(buf)
  if err!=nil {
   log.Printf("Tunnel interface unavailable: %v",err)
   return
  }
  // Only forward responses addressed to the authenticated client.
  if n<=0||n>maxFrame||!validIPv4(buf[:n],"","dst"){continue}
  packet:=append([]byte(nil),buf[:n]...)
  g.mu.RLock()
  active:=g.active
  if active!=nil {
    select {
    case active.outbound<-packet:
    default: // congestion: drop, never block the entire kernel tunnel
    }
  }
  g.mu.RUnlock()
 }
}
func (g *gateway) accept(c net.Conn){
 defer c.Close()
 _=c.SetDeadline(time.Now().Add(9*time.Second))
 var greeting [33]byte
 if _,err:=io.ReadFull(c,greeting[:]);err!=nil{return}
 if greeting[0]!=version||!validToken(greeting[1:],g.secret){
  log.Printf("Rejected tunnel authentication")
  return
 }
 s:=&session{conn:c,outbound:make(chan []byte,128),done:make(chan struct{})}
 g.mu.Lock()
 if g.active!=nil {
  g.mu.Unlock()
  log.Printf("Rejected connection: one device already connected")
  return
 }
 g.active=s
 g.mu.Unlock()
 defer func(){
  s.close()
  g.mu.Lock()
  if g.active==s{g.active=nil}
  g.mu.Unlock()
 }()
 if _,err:=c.Write([]byte{authorized});err!=nil{return}
 _=c.SetDeadline(time.Time{})
 log.Printf("Authenticated GhostForge client connected")
 // Serialized writer: frames from TUN and keepalives cannot interleave.
 go func(){
  ticker:=time.NewTicker(20*time.Second)
  defer ticker.Stop()
  for {
   select {
   case <-s.done:return
   case p:=<-s.outbound:
    _=c.SetWriteDeadline(time.Now().Add(12*time.Second))
    if err:=writeFrame(c,p);err!=nil{s.close();return}
   case <-ticker.C:
    _=c.SetWriteDeadline(time.Now().Add(12*time.Second))
    if err:=writeFrame(c,nil);err!=nil{s.close();return}
   }
  }
 }()
 // A client->gateway packet is injected into the kernel as if received from tun.
 // Kernel routing and NAT are configured by deploy.sh, not by this process.
 for {
  _=c.SetReadDeadline(time.Now().Add(80*time.Second))
  packet,err:=readFrame(c)
  if err!=nil{
    if !errors.Is(err,io.EOF){log.Printf("Tunnel disconnected: %v",err)}
    break
  }
  if len(packet)==0{continue}
  if !validIPv4(packet,"src",""){continue}
  if _,err:=g.tun.Write(packet);err!=nil{
    log.Printf("Tunnel packet injection failed: %v",err)
    break
  }
 }
 log.Printf("GhostForge client disconnected")
}

func main(){
 listen:=flag.String("listen","0.0.0.0:4443","TLS listener; firewall to authenticated clients where possible")
 iface:=flag.String("tun","ghostforge0","Linux TUN interface name (not Docker)")
 certPath:=flag.String("cert","","Path to publicly trusted TLS certificate (fullchain.pem)")
 keyPath:=flag.String("key","","Path to matching private key")
 flag.Parse()
 if *certPath==""||*keyPath==""{log.Fatal("Use --cert and --key (no insecure/self-signed TLS bypass)")}
 token,err:=tokenFromEnv()
 if err!=nil{log.Fatal(err)}
 cert,err:=tls.LoadX509KeyPair(*certPath,*keyPath)
 if err!=nil{log.Fatalf("Load TLS certificate: %v",err)}
 t,err:=openTun(*iface)
 if err!=nil{log.Fatal(err)}
 defer t.Close()
 listener,err:=tls.Listen("tcp",*listen,&tls.Config{
  MinVersion:tls.VersionTLS13,
  MaxVersion:tls.VersionTLS13,
  Certificates:[]tls.Certificate{cert},
 })
 if err!=nil{log.Fatalf("Listen: %v",err)}
 defer listener.Close()
 gateway:=&gateway{tun:t,secret:token}
 go gateway.tunReader()
 log.Printf("GhostForge Tunnel listening on %s; 1 authenticated client; IPv4 only",*listen)
 for {
  conn,err:=listener.Accept()
  if err!=nil{log.Fatalf("Accept: %v",err)}
  go gateway.accept(conn)
 }
}
