package main
import "C"
import "./utils"
import "./ipid_predict_lib"
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

//export spoofing_probe
func spoofing_probe(ip, dst_ip, proto string, port, dst_port int, domain string, n int, flag string) {
	//id := utils.ProbeIP(ip)
	utils.SpoofingProbe(ip, dst_ip, proto, uint16(port), uint16(dst_port), domain, uint16(n), flag)
}
 
//export testIP
func testIP(ip string, protocol string, port int, ns string, fs, sl int) (uintptr) { // return pointers: uintptr
	code, ids, _:= ipid_predict_lib.RscanIpidVelocityTestIPV3(ip, protocol, uint16(port), ns, fs, sl)
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

//export runTcpDump
func runTcpDump(sip, ip, pcapFile string, port int){
	//sudo timeout 6 tcpdump 'tcp[13] = 18' and src 194.0.130.53 -w test.pcap
	var wg sync.WaitGroup
	wg.Add(1)
	go func(pcapFile string){
		defer wg.Done()
		exec.Command("sudo","timeout", "5", "tcpdump", "src", ip, "-w", pcapFile).Output()
	}(pcapFile)
	p := strconv.Itoa(port)
	exec.Command("hping3", ip, "-S", "-p", p, "-c", "1",  "--spoof", sip).Output()
	//utils.SendTcpRequest(ip, "tcp", "-S", uint16(port)) 
	wg.Wait()
}

//export verifyGlobalRateLimit
func verifyGlobalRateLimit(sip1, sip2, ip, port, flag, rLow, rUp string) int {
	r_low, _ := strconv.Atoi(rLow)
	r_up, _ := strconv.Atoi(rUp)
	isGlobal := utils.GlobalRateLimit(sip1, sip2, ip, port, flag, r_low, r_up, 1)
	code := 0
	if !isGlobal{
		code = 1
	}
	return code
}

//export controlMeasureForIpid
func controlMeasureForIpid(sip, dst_ip, dst_port, flag, r string, n int) int {
	rint, _ := strconv.Atoi(r)
	code := utils.ControlMeasureForIpid(sip, dst_ip, flag, rint, n, dst_port)
	return code
}

//export censorMeasure
func censorMeasure(ip, port, flag, dst_ip, dst_port, rLow, rUp, td string, delay int) int {
	r_low, _ := strconv.Atoi(rLow)
	r_up, _ := strconv.Atoi(rUp)
	tdint, _ := strconv.Atoi(td)
	code := utils.CensorMeasure(ip, port, flag, dst_ip, dst_port, r_low, r_up, tdint, delay)
	return code
}

//export myComputeTd
func myComputeTd(sip, dst_ip string, dst_port int) int {
	td := utils.ComputeRtt(sip, dst_ip, uint16(dst_port))
	return td
}

//export dnsMeasure
func dnsMeasure(ip, proto, ns, cu, asn string, port int) int {
	code := utils.DnsProbe(ip, proto, "", uint16(port), ns, cu, asn)
	return code
}

//export setLogFile
func setLogFile(lfile string){
	f, err := os.OpenFile(lfile, os.O_RDWR | os.O_CREATE | os.O_APPEND , 0666)
	if err != nil {
		log.Fatalf("error opening log file: %v", err)
	}
	log.SetOutput(f)
}

//export dnsMeasureV2
func dnsMeasureV2(ip, proto, ns, cu, asn string, port int) *C.char {
	answered_ip := utils.DnsProbeV2(ip, proto, "", uint16(port), ns, cu, asn)
	return C.CString(answered_ip)
}


func main(){
	
}
