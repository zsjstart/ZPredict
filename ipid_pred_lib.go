package main
import "C"
import "./utils"
import "unsafe"
import "os/exec"
import "sync"
//import "fmt"
import "strconv"
import "log"
import "os"
import "C"

//export probe
func probe(ip, proto, flag string, port int, domain string) int {
	id := utils.RscanIpidVelocityTestIPV2(ip, proto, flag, uint16(port), domain) 
	return id
}

//export spoofing_probe
func spoofing_probe(ip, dst_ip, proto string, port, dst_port int, domain string, n int, flag string) {
	utils.SpoofingProbe(ip, dst_ip, proto, uint16(port), uint16(dst_port), domain, uint16(n), flag)
}
 
//export testIP
func testIP(ip string, protocol string, port int, ns string, fs, sl int) (uintptr) { // return pointers: uintptr
	code, ids, _:= utils.RscanIpidVelocityTestIPV3(ip, protocol, uint16(port), ns, fs, sl)
	//id := utils.ProbeIPUdp(ip)
	if code == -1 {
		ids = nil
		for i := 0; i < sl; i++{
			ids = append(ids, 0)
		}
		ids = append(ids, 1)
	} else {
		ids = append(ids, 0)
	}
	return uintptr(unsafe.Pointer(&ids[0]))	
}

func main(){
	
}
