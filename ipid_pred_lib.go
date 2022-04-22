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
	//id := utils.ProbeIP(ip)
	id := utils.RscanIpidVelocityTestIPV2(ip, proto, flag, uint16(port), domain) 
	return id
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
