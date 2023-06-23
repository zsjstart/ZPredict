package main
import "C"
import "./utils"
import "./ipid_predict_lib"
import "unsafe"
import "os/exec"
import "sync"
import "strconv"
//import "fmt"
import "time"
//import "math/rand"

//export probe
func probe(sip, ip, proto, flag string, port string, domain string) int {
	//id := utils.ProbeIP(ip)
	
	//port = int(10000 + (uint16(rand.Int()) & 0xffff) % 55535)
	Port,_ := strconv.Atoi(port)
	//fmt.Println(sip, ip, proto, flag, port)
	id := utils.RscanIpidVelocityTestIPV2(sip, ip, proto, flag, uint16(Port), domain) 
	return id
}

//export spoofing_probe
func spoofing_probe(ip, dst_ip, proto string, port, dst_port string, domain string, n string, flag string) {
	//id := utils.ProbeIP(ip)
	//fmt.Println(ip, dst_ip, proto, port, dst_port, n, flag)
	Port,_ := strconv.Atoi(port)
	Dst_Port,_ := strconv.Atoi(dst_port)
	N, _ := strconv.Atoi(n)
	utils.SpoofingProbe(ip, dst_ip, proto, uint16(Port), uint16(Dst_Port), domain, uint16(N), flag)
}
 
//export testIP
func testIP(sip0, sip1, ip string, protocol string, port string, ns, flag, fs, sl string) (uintptr) { // return pointers: uintptr
	
	Fs, _ := strconv.Atoi(fs)
	Sl, _ := strconv.Atoi(sl)
	Port,_ := strconv.Atoi(port)
	code, ids, _:= ipid_predict_lib.RscanIpidVelocityTestIPV3(sip0, sip1, ip, protocol, uint16(Port), ns, flag, Fs, Sl)
	
	//id := utils.ProbeIPUdp(ip)
	if code == -1 {
		ids = nil
		for i := 0; i < Sl; i++{
			ids = append(ids, 0)
		}
		ids = append(ids, 1)
	} else {
		ids = append(ids, 0)
	}
	return uintptr(unsafe.Pointer(&ids[0]))	
}

//export runTcpDump
func runTcpDump(ip, pcapFile string, port string){
	//sudo timeout 6 tcpdump 'tcp[13] = 18' and src 194.0.130.53 -w test.pcap
	
	Port,_ := strconv.Atoi(port)
	var wg sync.WaitGroup
	wg.Add(1)
	go func(pcapFile string){
		defer wg.Done()
		exec.Command("sudo","timeout", "6", "tcpdump", "src", ip, "-w", pcapFile).Output()
	}(pcapFile)
	time.Sleep(time.Duration(1000)*time.Millisecond)
	//exec.Command("hping3", ip, "-S", "-p", port, "-c", "1").Output()
	utils.SendTcpRequest(ip, "tcp", "-S", uint16(Port)) 
	wg.Wait()
}

//export verifyGlobalRateLimit
func verifyGlobalRateLimit(sip1, sip2, ip, flag, rLow, rUp string, dur int) int {
	r_low, err := strconv.Atoi(rLow)
	if err != nil{
		return 1
	}
	r_up, err := strconv.Atoi(rUp)
	if err != nil{
		return 1
	}
	isGlobal := utils.VerifyGlobalRateLimit(sip1, sip2, ip, flag, r_low, r_up, dur)
	if isGlobal{
		return 0
	}
	return 1
}

func main(){
	
}
