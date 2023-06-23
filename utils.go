package utils

import (
	"net"
	"time"
	"golang.org/x/net/ipv4"
	"math/rand"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"syscall"
	"strings"
	"sync"
	"bufio"
	"os"
	"strconv"
	"encoding/binary"
	"fmt"
	"crypto/tls"
	"math"	
	"context"
	
	//"github.com/aeden/traceroute"
	"os/exec"
	"reflect"
	"github.com/google/gopacket/pcap"
	
)

const TIMEOUT = 2000 * time.Millisecond

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// This file should be performed as SMap tester.

// GenID generates a random string with n bytes from [0-9A-Z].
func GenID(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(36)]
	}
	return string(b)
}

// SyncMap is a map[string]string with Sync Lock.
type SyncMap struct {
	sync.RWMutex
	m map[string]string
}
func NewSyncMap() *SyncMap {
	return &SyncMap{m: make(map[string]string)}
}
func (sm *SyncMap) Get(key string) string {
	defer sm.RUnlock() //UNlock reading
	sm.RLock() // Lock reading
	return sm.m[key]
}
func (sm *SyncMap) Set(key, value string) {
	sm.Lock()
	sm.m[key] = value
	sm.Unlock()
}

// SyncWriter is a bufio.Writer with Sync Lock.
type SyncWriter struct {
	sync.RWMutex
	w *bufio.Writer
	f *os.File
}
func NewSyncWriter(wfile string) *SyncWriter {
	outfile, err := os.Create(wfile)
    if err!=nil {
		log.Fatalf("error when opening output file: %v\n", err)
    }
	return &SyncWriter{
		w: bufio.NewWriter(outfile),
		f: outfile}
}
func (sw *SyncWriter) Write(values ...string) {
	if len(values)==0 { return }
	v := values[0]
	for i:=1; i<len(values); i++ {
		v += "," + values[i]
	}
	v += "\n"
	sw.Lock()
	_, err := sw.w.WriteString(v)
	if err!=nil {
		log.Printf("error when writing output(%v) to file: %v\n", v, err)
	}
	sw.w.Flush()
	sw.Unlock()
}
func (sw *SyncWriter) Close() {
	sw.f.Close()
}

// GetLocalIP returns local IP by dialing UDP.
func GetLocalIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
		log.Fatalf("error when getting local IP: %v\n", err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func Lookup(stype, domain string, ipnet *net.IPNet) net.IP{
	var spoofedIP net.IP
	spoofedIP = nil
	switch stype {
	case "ns":
		nSs, _ := resolver.LookupNS(context.Background(), domain)
		for _, nS := range nSs {
			ns := nS.Host
			if len(ns)<3 { continue } // why??
			if ns[len(ns)-1]=='.' { ns = ns[:len(ns)-1] }
			iPs, _ := resolver.LookupIPAddr(context.Background(), ns)
			//fmt.Println("ips:", "ns", iPs)
			for _, iP := range iPs {
				
				if iP.IP.To4() == nil { continue }
				ip := iP.IP.To4()
				if !ipnet.Contains(ip){ 
					spoofedIP = ip
					return spoofedIP
				}
			}
		}
	case "mx":
		mXs, _ := resolver.LookupMX(context.Background(), domain)
		for _, mX := range mXs {
			mx := mX.Host
			if len(mx)<3 { continue } // why??
			if mx[len(mx)-1]=='.' { mx = mx[:len(mx)-1] }
			iPs, _ := resolver.LookupIPAddr(context.Background(), mx)
			
			for _, iP := range iPs {
				
				if iP.IP.To4() == nil { continue }
				ip := iP.IP.To4()
				if !ipnet.Contains(ip){ 
					spoofedIP = ip
					return spoofedIP
				}
			}
		}
	case "www":
		fqdns := make([]string, 0, 2)
		fqdns = append(fqdns, domain)
		fqdns = append(fqdns, "www."+domain)
		for _, fqdn := range fqdns {
			iPs, _ := resolver.LookupIPAddr(context.Background(), fqdn)
			
			for _, iP := range iPs {
				if iP.IP.To4() == nil { continue }
				ip := iP.IP.To4()
				if !ipnet.Contains(ip){ 
					spoofedIP = ip
					return spoofedIP
				}
			}
		}
	
	}
	return spoofedIP

}



var resolver *net.Resolver
func GetSpoofedIP(extIP, domain string) net.IP {
	var spoofedIP net.IP
	spoofedIP = nil
	extip, ipnet, err := net.ParseCIDR(extIP+"/24")
	if err != nil {
		return spoofedIP
	}


	resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", net.JoinHostPort("8.8.8.8", "53"))
			},
		}

	spoofedIP = Lookup("ns",domain, ipnet)
	
	if spoofedIP == nil {
		spoofedIP = Lookup("mx",domain, ipnet)
	    	
	}

	if spoofedIP == nil {

		spoofedIP = Lookup("www",domain, ipnet)
	}
	
	if spoofedIP == nil {

		ip4 := extip.To4()
		ip4[3] = 255
		inc(ip4)
		inc(ip4)
		spoofedIP = ip4
	}

	return spoofedIP		
}

// GetNeighbour returns neighbour IP.
func GetNeighbour(ip string) net.IP {
	ip4 := net.ParseIP(ip).To4()
	ip4[3] ^= 0x0001
	return ip4
		
}

func htons(value int) int {
	return (((value&0xff)<<8) | ((value&0xff00)>>8))
}


/////////////////////////////////////////////////////////My Func
type Scanner struct {
	ips []net.IP
	timeout time.Duration
	protocol string
}

func NewScanner(options ...func(*Scanner)) *Scanner {
	scanner := Scanner {
		timeout: time.Second,
		protocol: "tcp",
	}

	for _, option := range options {
		option(&scanner)
	}
	return &scanner
}

func WithTimeout(timeout time.Duration) func(*Scanner) {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

func WithProtocol(protocol string) func(*Scanner) {
	return func(s *Scanner) {
		s.protocol = protocol
	}

}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

type AddressSet struct {
	ip       string
	port     uint16
	protocol string
	ids      []int
	times	 []time.Time
	velocity int
	rtt      int
}


func (s *Scanner) AddCIDR(cidr string) (net.IP, error) {
	
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	for ip0 := ip.Mask(ipnet.Mask); ipnet.Contains(ip0); inc(ip0) {
		    s.ips = append(s.ips, copyIP(ip0)) // 256 IP addresses
	}
	return ip, nil
}


func (s *Scanner) Scan(sip, sport string, port uint16, scan_type, domain string, v_thres int, targetChan chan AddressSet) []AddressSet {
	results := []AddressSet{}
	guard := make(chan bool, 256) 
	
	sm := sync.Mutex{}
	var wg sync.WaitGroup

	start := time.Now()
	
	for _, ip := range s.ips {
		t := time.Now()
		if t.Sub(start) > s.timeout { break }
		ip4 := fmt.Sprintf("%s", ip)
		//port := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		//test: using tcp port 80 to scan the subnetwork to identify the idle hosts
		
		wg.Add(1)
		go func(ip4 string, port uint16){
			defer wg.Done()
			
			guard <- true
			code, ids, times, velocity, rtt := preproc(ip4, sip, sport, port, s.protocol, scan_type, domain, v_thres)
			<- guard
			if code == 0 {
				sm.Lock()
				results = append( results, AddressSet{
					ip:       ip4,
					port:     port,
					protocol: s.protocol,
					ids:      ids,
					times:    times,
					velocity: velocity,
					rtt:      rtt,
					
				})
				targetChan <- AddressSet{
					ip:       ip4,
					port:     port,
					protocol: s.protocol,
					ids:      ids,
					times:    times,
					velocity: velocity,
					rtt:      rtt,
					
				}
				sm.Unlock()
			} else {
				targetChan <- AddressSet{}
			}	
			
			
		}(ip4, port)
			
	}
	wg.Wait()
	return results
}

func pre_filter(ids []int) (int, []int) {
	length := len(ids)
	if length == 4 { 
		count_nega := 0
		for _, id := range ids {
			if id < 0 {
				count_nega++
			}
		}
		if count_nega == 4 {
			return -1, ids
		}
	} // can filter out no responses
	id0 := ids[length-2]
	id1 := ids[length-1]
	if id0 < 0 || id1 < 0 {
		return 0, ids
	} 

	if diff(id0, id1) == 0 { return -1, ids} // can filter out constant ipid

	if diff(id0, id1) > 800 { return -1, ids} // It is the first filter. Remove the case in which the target do not apply a single IPID stack for different ip addresses, if more than 800 IPID/s cannot identify the difference between global IPID and random IPID
	return 0, ids
}

// In the current coding, ids has not been used. 
// This method works to verify if the modified IPID technique is appliable or not. 
// 0: appliable and non-spoofable, 1: spoofable, -1: non-applicable, -2: errors during the measurement
func preproc(ip, sip, sport string, port uint16, protocol string, scan_type, domain string, v_thres int) (int, []int, []time.Time, int, int) {
	
	ids := []int{}
	times := make([]time.Time, 0)
	rtts := make([]float64, 0)
	v := -9999
	rtt := 0
	
	probes := 10
	switch protocol {
	case "tcp":
		c, rc := CreateRawConn("tcp")
	        defer c.Close()
	        defer rc.Close()
		
		timeout := 1500 * time.Millisecond
	
		var srcIP string
		for i := 0; i< probes; i=i+2{
			srcIP = "199.244.49.220"
			id0 := RscanGetIpidByTcp(rc, srcIP, ip, port, timeout, scan_type)
			ids = append(ids, id0)
			times = append(times, time.Now())
			if id0 == 0 { return -1, ids, times, v, rtt}
			
			srcIP = "199.244.49.62"
			id1 := RscanGetIpidByTcp(rc, srcIP, ip, port, timeout, scan_type)
			ids = append(ids, id1)
			times = append(times, time.Now())
			if id1 == 0 { return -1, ids, times, v, rtt}
			
			if diff(id0, id1) == 0 { return -1, ids, times, v, rtt} // constant IPID

			if id0 < 0 || id1 < 0 {
				time.Sleep(200 * time.Millisecond) // not filter out the cases of no responses received
				continue
			} 
			if diff(id0, id1) > 200 { return -1, ids, times, v, rtt} // remove the case in which the target do not apply a single IPID stack for different ip addresses 
			time.Sleep(200 * time.Millisecond)
		} 
	
	case "udp":
		
		timeout := 1500 * time.Millisecond
		
		var srcIP string
		for i := 0; i< probes; i=i+2{
			srcIP = "199.244.49.220"
			id0 := RscanGetIpidByUdp(nil, srcIP, ip, domain, port, timeout)
			ids = append(ids, id0)
			times = append(times, time.Now())
			if id0 == 0 { return -1, ids, times, v, rtt}
			
			srcIP = "199.244.49.62"
			id1 := RscanGetIpidByUdp(nil, srcIP, ip, domain, port, timeout)
			ids = append(ids, id1)
			times = append(times, time.Now())
			if id1 == 0 { return -1, ids, times, v, rtt}

			if diff(id0, id1) == 0 { return -1, ids, times, v, rtt} // constant IPID

			if id0 < 0 || id1 < 0 {
				time.Sleep(200 * time.Millisecond) // not filter out the cases of no responses received
				continue
			} 
			if diff(id0, id1) > 200 { return -1, ids, times, v, rtt} // remove the case in which the target do not apply a single IPID stack for different ip addresses 
			time.Sleep(200 * time.Millisecond)
			
		} 
		
	case "icmp":
		c, rc := CreateRawConn("icmp")
	        defer c.Close()
	        defer rc.Close()
		//timeout := SetRecTimeout(ip, port, "icmp")
		timeout := 1500 * time.Millisecond
                
		var srcIP string
		for i := 0; i< probes; i=i+2{
			srcIP = "199.244.49.220"
			id0, rtt0 := RscanGetIpidByIcmp(rc, srcIP, ip, timeout)
			ids = append(ids, id0)
			times = append(times, time.Now())
			if id0 == 0 { return -1, ids, times, v, rtt}
			if id0 > 0 { rtts = append(rtts, rtt0)}
			
			srcIP = "199.244.49.62"
			id1, rtt1 := RscanGetIpidByIcmp(rc, srcIP, ip, timeout)
			ids = append(ids, id1)
			times = append(times, time.Now())
			if id1 == 0 { return -1, ids, times, v, rtt}
			if id1 > 0 { rtts = append(rtts, rtt1)}
			
			code, ids := pre_filter(ids)
			if code == -1 { return -1, ids, times, v, rtt}
			time.Sleep(200 * time.Millisecond)
		} 
		
	}
	
	count_nega := 0
	for _, id := range ids {
		if id < 0 {
			count_nega++
		}
	}
	if float64(count_nega)/float64(len(ids)) > 0.3 { return -1, ids, times, v, rtt} //ensure that there must be two IP ID values are from another ip addresses. 
	
	new_ids, new_times := filter_nega(ids, times)
	isSeqAndIdle, v := IpidSequentialAndIdle(new_ids, new_times, v_thres)
        if !isSeqAndIdle { 
		return -1, ids, times, v, rtt
	} 
	sum := 0.0
	for _, r := range rtts {
		sum += r
	}
	if len(rtts) != 0 {
		rtt = int(sum)/len(rtts)
	}

	return 0, ids, times, v, rtt
}

func filter_nega(ids []int, times []time.Time) ([]int, []time.Time){
	new_ids := make([]int, 0)
	new_times := make([]time.Time, 0)
	for i, id := range ids {
		if id < 0 {
			continue
		}
		new_ids = append(new_ids, ids[i])
		new_times = append(new_times, times[i])
	}
	return new_ids, new_times
}

func IsIdle(ids []int) bool {
	mean_diff :=float64(ids[len(ids)-1]-ids[0])/float64(len(ids)-1)
	if mean_diff >= 5 { return false}
	//s := 0.0
	//for i := 0; i < len(ids)-1; i++ {
	//	s += math.Pow(float64(ids[i+1]-ids[i])-mean_diff,2)
	//}
	//s =  math.Sqrt(s/float64(len(ids)-1))
	//if s > 10 { // this threshold 10 not sure!!!!
        //   return false
	//}
	return true	
}

func IsIdleV2(ids []int, times []time.Time)bool{
	var v int
	spd := float64(0)
	for i:=0; i<len(ids)-1; i++ {
		gap := float64(diff(ids[i], ids[i+1]))
		dur := float64(times[i+1].Sub(times[i]).Nanoseconds())/1000000000.0 //unit: ID/s
		spd += gap/dur
	}
	spd /= float64(len(ids)-1)
	v = int(spd)
	log.Printf("The velocity observed of %v:%v\n", ids, v)
	if v <= 10 {
		return true
	}
	return false
}

func probing(ip, protocol string, port uint16, domain string, writer *SyncWriter){
	per := RscanIpidVelocityTestIPV2("", ip, protocol, "S", port, domain)
	if per == 1.0 {
		writer.Write(ip, fmt.Sprint(per), protocol)
		//res[ip] = append(res[ip], fmt.Sprint(ids), fmt.Sprint(times))
	}
	log.Printf("%v, %v,%v", ip, protocol, per)
}

func RscanIpidVelocityTest(cidr, protocol string, port uint16, domain string, writer_icmp, writer_tcp, writer_udp *SyncWriter) map[string][]string {
	//guard1 := make(chan bool, 25)
	//guard2 := make(chan bool, 25)
	guard3 := make(chan bool, 50)
	res := make(map[string][]string)
	timeout := 5*time.Second
	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
	_,err := scanner.AddCIDR(cidr)
	if err != nil {
		log.Printf("Error in parsing cidr: %v,%v", cidr, protocol)
	}
	//sm := sync.Mutex{}
	var wg sync.WaitGroup

	for _, extIP := range scanner.ips {
		wg.Add(1)
		ip := fmt.Sprintf("%s", extIP)

		go func(ip string) {
			defer wg.Done()
			//guard1 <- true
			//probing(ip, "icmp", uint16(0), "", writer_icmp)
			//<- guard1
			//time.Sleep(1000*time.Millisecond)
			//guard2 <- true
			//probing(ip, "tcp", uint16(80), "", writer_tcp)
			//<- guard2
			//time.Sleep(1000*time.Millisecond)
			guard3 <- true
			probing(ip, "udp", uint16(33435), "", writer_udp)
			<- guard3
			
		}(ip)
	}

	wg.Wait()
	
	return res
}

func RscanIpidVelocityTest01(cidr, protocol string, port uint16, domain string) map[string][]string {
	guard := make(chan bool, 50)
	res := make(map[string][]string)
	timeout := 5*time.Second
	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
	_,err := scanner.AddCIDR(cidr)
	if err != nil {
		log.Printf("Error in parsing cidr: %v,%v", cidr, protocol)
	}
	sm := sync.Mutex{}
	var wg sync.WaitGroup

	for _, extIP := range scanner.ips {
		wg.Add(1)
		ip := fmt.Sprintf("%s", extIP)
		go func(ip string) {
			defer wg.Done()
			guard <- true
			code,ids, times := RscanIpidVelocityTestIPV3(ip, protocol, port, domain)
			<- guard
			if code == 0 {
				sm.Lock()
				res[ip] = append(res[ip], fmt.Sprint(ids), fmt.Sprint(times))
				sm.Unlock()
			}
			log.Printf("%v, %v, %v", ip, ids, times)
		}(ip)
	}

	wg.Wait()
	return res
}

func SpoofingProbe(ip, dst_ip, proto string, port, dst_port uint16, domain string, num uint16, flag string){
	localIP := net.ParseIP(ip).To4()
	extIP := net.ParseIP(dst_ip).To4()
	prob_rate := 1000
	for i := uint16(0); i < num; i++ {
		switch proto {
		case "icmp":
			id := uint16(rand.Int()) & 0xffff
			seq := uint16(rand.Int()) & 0xffff
			SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
		case "tcp":
			switch flag { 
			case "control":                       
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535 // Should be random source port; otherwise it is the same socket in the spoofing
				//localPort := port //it should be port when test_pred_n
				//dst_port := 10000 + (uint16(rand.Int()) & 0xffff) % 55535 // it should be random when test_pred_n
				seq := uint32(rand.Int()) & 0xffffffff
				SendTcpByRawConn(nil, localIP, extIP, localPort, dst_port, "SA", seq, 0, 1, nil) //should be 'SA' when test_pred_n, 'SA' in our port scan but 'S' in smap
			case "test":
				
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535 // Should be random source port; otherwise it is the same socket in the spoofing
				seq := uint32(rand.Int()) & 0xffffffff
				SendTcpByRawConn(nil, localIP, extIP, localPort, dst_port, "S", seq, 0, 1, nil) 
			}
		case "udp":
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			txid := uint16(rand.Int()) & 0xffff
			SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
		}
		time.Sleep(time.Duration(1.0/float64(prob_rate)*1000)*time.Millisecond)
	}
}

func SendTcpRequest(ip, proto, flag string, port uint16) {
	if proto != "tcp"{
		return
	}
	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	seq := uint32(rand.Int()) & 0xffffffff
	SendTcpByRawConn(nil, localIP, extIP, localPort, port, "S", seq, 0, 1, nil)
}

func RscanIpidVelocityTestIPV2(sip, ip, proto, flag string, port uint16, domain string) (int) {
	ipid := -1
	//localIP := GetLocalIP()
	localIP := net.ParseIP(sip).To4()
	extIP := net.ParseIP(ip).To4()
	timeout := 950 * time.Millisecond
	var riph *ipv4.Header
	//var packet gopacket.Packet
	switch proto {
	case "icmp":
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(rand.Int()) & 0xffff
		SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
		
		riph, _ = RscanRecvByRawConn(nil, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout) 
	case "tcp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		seq := uint32(rand.Int()) & 0xffffffff
		if flag == "SA"{
			SendTcpByRawConn(nil, localIP, extIP, localPort, port, "SA", seq, 0, 1, nil)
			riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, 0, "tcp", "RA,R", "", 0, nil, timeout) //should be "RA,R"
		}
		if flag == "S"{
			SendTcpByRawConn(nil, localIP, extIP, localPort, port, "S", seq, 0, 1, nil)
			
			riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, 0, "tcp", "SA", "", 0, nil, timeout) //SA or A
			//SendTcpByRawConn(nil, dstIP, srcIP, uint16(dstPort), uint16(srcPort), "RA", 0, ack, 1, nil)
		}
		// afterwards, the kernel will automaticall send a RST to stop the connection 
	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		txid := uint16(rand.Int()) & 0xffff
		SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
		//riph, _ = RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's
		riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "udp", 0, nil, timeout)
		
		/*if riph != nil {
		
			if l := packet.Layer(layers.LayerTypeDNS); l!=nil {
				rdnsl, ok := l.(*layers.DNS)
				if ok {
					for _, answer := range(rdnsl.Answers) {
						if answer.Type == layers.DNSType(1) {
							web_ip = answer.IP.String()
							break
						}
					}
				}
			}
		}*/
	}
	if riph != nil {
		ipid =  riph.ID
	}
	
	return ipid

}


func RscanIpidVelocityTestIPV3(ip string, proto string, port uint16, domain string) (int, []int, []int64) {
	ids := []int{}
	times := make([]int64, 0)
	code := 0
	prob_rate := 1 //1
	probes := 4 //60
	
	//timeout := SetRecTimeout(ip, port, "icmp")
	timeout := 950* time.Millisecond //950
        sm := sync.Mutex{}
	extIP := net.ParseIP(ip).To4()
	var wg sync.WaitGroup
	for i := 0; i< probes; i=i+2{

		if i >  10 {
			count_nega := 0
			for _, id := range ids {
				if id < 0 {
					count_nega++
				}
			}
			if count_nega > 10 {
				return -1, ids, times
			}
		}
	
		
		
		wg.Add(1)
		go func() {
			defer wg.Done()
			//localIP := GetLocalIP()
			//localIP := net.ParseIP("199.244.49.62").To4()
			//localIP := net.ParseIP("198.22.162.189").To4()
			localIP := net.ParseIP("45.125.236.166").To4()
			ipid := 0
			
			var riph *ipv4.Header
			switch proto {
			case "icmp":
				id := uint16(rand.Int()) & 0xffff
				seq := uint16(rand.Int()) & 0xffff
				SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
				riph, _ = RscanRecvByRawConn(nil, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout) 
			case "tcp":
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				seq := uint32(rand.Int()) & 0xffffffff
				SendTcpByRawConn(nil, localIP, extIP, localPort, port, "S", seq, 0, 1, nil) //SA
				riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, 0, "tcp", "SA", "", 0, nil, timeout) //R
				// afterwards, the kernel will automaticall send a RST to stop the connection 
			case "udp":
				//_, riph = RscanSendIpidByUdp(localIP, extIP, port, timeout)
				
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
				riph, _ = RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
			}
			if riph == nil {
				ipid = -1 // no response
			} else {
				ipid =  riph.ID
			}
			sm.Lock()
			ids = append(ids, ipid)
			times = append(times, time.Now().UnixNano())
			sm.Unlock()
		}()
		time.Sleep(time.Duration(1.0/float64(prob_rate)*1000)*time.Millisecond)
		wg.Add(1)
		go func() {
			defer wg.Done()
			//localIP := GetLocalIP()
			//localIP := net.ParseIP("199.244.49.220").To4()
			//localIP := net.ParseIP("198.22.162.67").To4()
			localIP := net.ParseIP("45.125.236.167").To4()
			ipid := 0
			var riph *ipv4.Header
			switch proto {
			case "icmp":
				id := uint16(rand.Int()) & 0xffff
				seq := uint16(rand.Int()) & 0xffff
				SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
				riph, _ = RscanRecvByRawConn(nil, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout) 
			case "tcp":
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				seq := uint32(rand.Int()) & 0xffffffff
				SendTcpByRawConn(nil, localIP, extIP, localPort, port, "S", seq, 0, 1, nil) //SA
				riph, _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, 0, "tcp", "SA", "", 0, nil, timeout) //R
				// afterwards, the kernel will automaticall send a RST to stop the connection 
			case "udp":
				//_, riph = RscanSendIpidByUdp(localIP, extIP, port, timeout)
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
				riph, _ = RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil)
			
			}
			if riph == nil {
				ipid = -1 // no response
			} else {
				ipid =  riph.ID
			}
			sm.Lock()
			ids = append(ids, ipid)
			times = append(times, time.Now().UnixNano())
			sm.Unlock()
		}()
		
		time.Sleep(time.Duration(1.0/float64(prob_rate)*1000)*time.Millisecond)
	} 
	wg.Wait()
	count_nega := 0
	for _, id := range ids {
		if id < 0 {
			count_nega++
		}
	}
	if float64(count_nega)/float64(len(ids)) > 0 { return -1, ids, times}
	return code, ids, times
}

func ProbeIP(ip string) (int) {
	c, rc := CreateRawConn("icmp")
	defer c.Close()
	defer rc.Close()
	//timeout := SetRecTimeout(ip, port, "icmp")
	timeout := 1000 * time.Millisecond
        localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	id := uint16(rand.Int()) & 0xffff
	seq := uint16(rand.Int()) & 0xffff
	// ICMP TypeCode = (8, 0) = 8 * 256 + 0 = Echo
	ok := SendIcmpByRawConn(rc, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
	if ok == -1 { return -1}
	
	// ICMP TypeCode = (0, 0) = 0 * 256 + 0 = Echo Reply
	riph, _ := RscanRecvByRawConn(rc, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout) 
	if riph == nil { return -1}
	return riph.ID
}

func ProbeIPUdp(ip string) (int) {
	//timeout := SetRecTimeout(ip, port, "icmp")
	port := uint16(53)
	domain := "www.google.com"
        localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	txid := uint16(rand.Int()) & 0xffff
	SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
	riph, _ := RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // timeout := 1000 * time.Millisecond
	if riph == nil { return -1}
	return riph.ID
}


func RscanIpidVelocityTestIP(ip string) (int, []int, int) {
	ids := []int{}
	times := make([]time.Time, 0)
	v := -9999
	probes := 10
	c, rc := CreateRawConn("icmp")
	defer c.Close()
	defer rc.Close()
	//timeout := SetRecTimeout(ip, port, "icmp")
	timeout := 2000 * time.Millisecond
        
	var srcIP string
	for i := 0; i< probes; i=i+2{
		srcIP = "199.244.49.220"
		id0, _ := RscanGetIpidByIcmp(rc, srcIP, ip, timeout)
		ids = append(ids, id0)
		times = append(times, time.Now())
		if id0 == 0 { return -1, ids, v}
		
		srcIP = "199.244.49.62"
		id1, _ := RscanGetIpidByIcmp(rc, srcIP, ip, timeout)
		ids = append(ids, id1)
		times = append(times, time.Now())
		if id1 == 0 { return -1, ids, v}
		
		code, ids := pre_filter(ids)
		if code == -1 { return -1, ids, v}
		time.Sleep(200 * time.Millisecond)
	} 
	
	count_nega := 0
	for _, id := range ids {
		if id < 0 {
			count_nega++
		}
	}
	if float64(count_nega)/float64(len(ids)) > 0.3 { return -1, ids, v} 
	
	new_ids, new_times := filter_nega(ids, times)
	// The second filter to remove the cases not using a shared IPID counter 
	for i := 0; i < len(new_ids)-1; i++ {
		if diff(ids[i], ids[i+1]) > 800 { // To ensure that the difference of any successive IPIDs is not more than 800 ID/s
			return -1, ids, v
		}
	}

	v = ComputeIpidVelocity(new_ids, new_times)
	return 0, ids, v
}

func ComputeIpidVelocity(ids []int, times []time.Time) int {
	v := -9999
	spd := float64(0)
	for i:=0; i<len(ids)-1; i++ {
		gap := float64(diff(ids[i], ids[i+1]))
		dur := float64(times[i+1].Sub(times[i]).Nanoseconds())/1000000000.0 //unit: ID/s
		spd += gap/dur
	}
	spd /= float64(len(ids)-1)
	v = int(spd)
	return v
}


func RscanIdleHostScan(rscan_addr AddressSet, extIP net.IP, port uint16) (int, []int){
	       rscanip := rscan_addr.ip 
	       //protocol := rscan_addr.protocol  
	       c, rc := CreateRawConn("icmp")
	       defer c.Close()
	       defer rc.Close()
	       // set a suitable timeout
               //timeout := SetRecTimeout(rscanip, 0, protocol)
	       timeout := 1500 * time.Millisecond
	       ids := make([]int, 5, 5)
	       times := make([]time.Time, 5, 5)
	       normals := 4
	
	       for i:= 0; i<normals; i++ {
	    	   ids[i], _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout) // my test: Rscan 
	    	   times[i] = time.Now()
	    	}
		//localIP := GetLocalIP()
		spoofedIP := net.ParseIP(rscanip).To4()	
		
		var wg sync.WaitGroup
		probes := 10
		for i := 0; i<probes; i++ {
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			wg.Add(1)
			go func(localPort uint16) {
				defer wg.Done()
				SendTcpByRawConn(rc, spoofedIP, extIP, localPort, port, "S", 0, 0, 1, nil)
			}(localPort)		
		} 
		wg.Wait()
		//MyRecvByRawConn(rc, extIP, localIP, port, 8888, 0, "tcp", "T", "", 0, nil)
		
		//time.Sleep(20*time.Duration(probes))
		ids[normals], _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout)
		times[normals] = time.Now()
		
		if IpidErr(ids) { 
			
			return -3, ids
			
		}
		if MyIpidSpoofable(extIP.String(), ids, times, probes, 0) {
			
			return 1, ids
			
		} 
	return 0, ids
}

func RscanIpidTestIcmp02(cidr, sip, sport string, port uint16) (int, []int) {
	idset := []int{}
	timeout := 5*time.Second /// it should be changed
	protocol := "icmp"
     	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol))
     	ip,err := scanner.AddCIDR(cidr)
     	if err != nil {   
     	   return -3, idset
     	}
	extIP := ip.To4()
	addrset := scanner.Scan(sip, sport, port, "tcp SYN connect", "", 10, nil)
	//log.Println("result: ", extIP.String(), addrset)
	if len(addrset) == 0 {		
		return -1, idset
	}
      	
	// to reduce false positive, filtering the hosts that are too busy...
	newAddrset := []AddressSet{}
	for _, addr := range addrset {
	       ids := addr.ids
	       if IsIdle(ids) {
			newAddrset = append(newAddrset, addr)
		} else {
			continue
		}  
	}
	if len(newAddrset) == 0 { //not found idle host 
		return -1, idset
	}
	log.Println("Idle hosts Addrset: ", extIP.String(), newAddrset)

	
        for _, addr := range newAddrset {	       
	       code, ids := RscanIdleHostScan(addr, extIP, port)
	       if code == 1 { //spoofable
		
	          log.Println("idle_host", extIP.String(), addr, ids)
		  return 1, idset
		}

	}
	
	
	return 0, idset
}

func MyIpidTestIcmpV2(ip, spoofed_ip, sip, sport string) (int, []int) {
		code, ids, times, v, _ := preproc(ip, sip, sport, uint16(0), "icmp", "none", "", 100)
		if (code < 0) {
			return code, ids //-2: error; -1: icmp packets were filtered or blocked
		}

		rscanip := ip
		channel := make(chan *ipv4.Header, 2)
		timeout := 1500*time.Millisecond

		dstIP := net.ParseIP(rscanip).To4()
		srcIP0 := net.ParseIP("199.244.49.220").To4()
		id0 := uint16(rand.Int()) & 0xffff
		seq0 := uint16(rand.Int()) & 0xffff
		ok := SendIcmpByRawConn(nil, srcIP0, dstIP, []uint16{8*256, id0, seq0}, 1, nil)
		if ok == -1 { return -5, ids}
		go func(){
			riph0, _ := RscanRecvByRawConn(nil, dstIP, srcIP0, 0, 0, 0, "icmp", "", "first", 0, []uint16{0, id0, seq0}, timeout) // timeout=500ms
			channel <- riph0
		}()
		time.Sleep(1*time.Millisecond)

		spoofedIP := net.ParseIP(spoofed_ip).To4()
		log.Println(rscanip, "using spoofing IP:", spoofedIP)

		probes := 2
		num := probes
		for i := 0; i<probes; i++ {
			id := uint16(rand.Int()) & 0xffff
			seq := uint16(rand.Int()) & 0xffff
			ok := SendIcmpByRawConn(nil, spoofedIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
			if ok == -1 { num-- }
			time.Sleep(1*time.Millisecond)
		} 
		if num == 0 { return -6, ids} // failure in sending spoofed packets
		probes = num
		
		srcIP1 := net.ParseIP("199.244.49.220").To4()
		id1 := uint16(rand.Int()) & 0xffff
		seq1 := uint16(rand.Int()) & 0xffff
		ok = SendIcmpByRawConn(nil, srcIP1, dstIP, []uint16{8*256, id1, seq1}, 1, nil)
		if ok == -1 { return -7, ids}
		go func(){
			riph1, _ := RscanRecvByRawConn(nil, dstIP, srcIP1, 0, 0, 0, "icmp", "", "second", 0, []uint16{0, id1, seq1}, timeout) // timeout=500ms
			channel <- riph1
		}()
		
		counter := 0
		for riph := range channel {
			if riph == nil { return -3, ids}
			id := riph.ID
			ids = append(ids, id)
			times = append(times, time.Now())
			if id == 0 { return -3, ids}
			counter++
			if counter == 2 { break}
		}
	     	
		new_ids, _ := filter_nega(ids, times)
		// update threshold when all of the IPID values observed are even: probes = 2*probes
		num_even := 0
		for _, id := range new_ids {
			if  (id % 2 == 0) {
				num_even++	
			}
		}
		if len(new_ids) == num_even {
			probes = 2*probes
		}
		
		if MyIpidSpoofable(rscanip, ids, times, probes, v) {
			
			return 1, ids
			
		} 
		
	return 0, ids	
}

func MyIpidTestIcmp(ip, spoofed_ip, sip, sport string) (int, []int) {
	       code, ids, times, v, _ := preproc(ip, sip, sport, uint16(0), "icmp", "none", "", 50)
	       if (code < 0) {
			return code, ids //-2: error; -1: icmp packets were filtered or blocked
	       }

	       rscanip := ip
	       c, rc := CreateRawConn("icmp")
	       defer c.Close()
	       defer rc.Close()
	       timeout := 1500*time.Millisecond
	       id := -9999
	       id, _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout)
    	       ids = append(ids, id)
	       times = append(times, time.Now())
	       if id <= 0 {
		  return -3, ids
	       } // errors or weird cases during spoofing
	   
		spoofedIP := net.ParseIP(spoofed_ip).To4()
		log.Println(rscanip, "using spoofing IP:", spoofedIP)
		dstIP := net.ParseIP(rscanip).To4()
		probes := 2	
		var wg sync.WaitGroup
		for i := 0; i<probes; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				id := uint16(rand.Int()) & 0xffff
				seq := uint16(rand.Int()) & 0xffff
				SendIcmpByRawConn(rc, spoofedIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				time.Sleep(1*time.Millisecond)
			}()		
		} 
		wg.Wait()
		time.Sleep(1*time.Millisecond)
		id, _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout)
		ids = append(ids, id)
		times = append(times, time.Now())
		log.Println("ids: ", rscanip, spoofedIP, ids, v)
		if id <= 0 { return -3, ids}
		
		new_ids, _ := filter_nega(ids, times)
		// update threshold when all of the IPID values observed are even: probes = 2*probes
		num_even := 0
		for _, id := range new_ids {
			if  (id % 2 == 0) {
				num_even++	
			}
		}
		if len(new_ids) == num_even {
			probes = 2*probes
		}

		if MyIpidSpoofable(rscanip, ids, times, probes, v) {
			
			return 1, ids
			
		} 
		
	return 0, ids	
}

func RscanIpidTestIcmp(cidr, sip, sport string, port uint16) (int, []int) {
	idset := []int{}
	timeout := 5*time.Second
	protocol := "icmp"
     	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol))
     	ip,err := scanner.AddCIDR(cidr)
     	if err != nil {   
     	   return -3, idset
     	}
	extIP := ip.To4()
	addrset := scanner.Scan(sip, sport, port, "tcp SYN connect", "", 10, nil)
	log.Println("result: ", extIP.String(), addrset)
	if len(addrset) == 0 {
		
		return -1, idset
	}
      	
	// to reduce false positive, filtering the hosts that are too busy...
	newAddrset := []AddressSet{}
	for _, addr := range addrset {
	       ids := addr.ids
	       if IsIdle(ids) {
			newAddrset = append(newAddrset, addr)
		} else {
			continue
		}  
	}
	if len(newAddrset) == 0 { //not found idle host 
		return -1, idset
	}
	log.Println("newAddrset: ", extIP.String(), newAddrset)
	ids0 := newAddrset[0].ids
	min_diff := (ids0[len(ids0)-1]-ids0[0])/(len(ids0)-1)
	rscan_addr := newAddrset[0]
        for _, addr := range newAddrset {	       
	       ids := addr.ids
	       ipid_diff := (ids[len(ids)-1]-ids[0])/(len(ids)-1)
	       if ipid_diff < min_diff {
		  min_diff = ipid_diff
	          rscan_addr = addr
		}
	}
	
	      
	       rscanip := rscan_addr.ip
	       
	       c, rc := CreateRawConn("icmp")
	       defer c.Close()
	       defer rc.Close()
	       rectimeout := 1500 * time.Millisecond
	       ids := make([]int, 5, 5)
	       times := make([]time.Time, 5, 5)
	       normals := 4
	       for i:= 0; i<normals; i++ {
	    	   ids[i], _ = RscanGetIpidByIcmp(rc, "", rscanip, rectimeout) // my test: Rscan 
	    	   times[i] = time.Now()
	    	}
		//localIP := GetLocalIP()
		spoofedIP := net.ParseIP(rscanip).To4()	
		
		var wg sync.WaitGroup
		probes := 10
		for i := 0; i<probes; i++ {
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			wg.Add(1)
			go func(localPort uint16) {
				defer wg.Done()
				SendTcpByRawConn(rc, spoofedIP, extIP, localPort, port, "S", 0, 0, 1, nil)
			}(localPort)		
		} 
		wg.Wait()
		//MyRecvByRawConn(rc, extIP, localIP, port, 8888, 0, "tcp", "T", "", 0, nil)
		
		//time.Sleep(20*time.Duration(probes))
		ids[normals], _ = RscanGetIpidByIcmp(rc, "", rscanip, rectimeout)
		times[normals] = time.Now()
		
		if IpidErr(ids) { 
			
			return -3, idset
			
		}
		if MyIpidSpoofable(ip.String(), ids, times, probes, 0) {
			
			return 1, idset
			
		} 

	return 0, idset
}

func RscanSendUdpByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort uint16, rn int) int {
        
	if rawConn == nil {
		c, rc := CreateRawConn("udp")
                
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	wntpl := &layers.NTP{
		LeapIndicator: 0,
		Version: 3,
		Mode: 3,
	}
	

	tipl := &layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	wudpl := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	wudpl.SetNetworkLayerForChecksum(tipl)

	sbuf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths:true, ComputeChecksums:true}
	gopacket.SerializeLayers(sbuf, sopts,
		wudpl,
		wntpl,
	)
	wb := sbuf.Bytes()

	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			0,
		FragOff:	0,
		TTL:		64,
		Protocol:	int(layers.IPProtocolUDP),
		Checksum:	0,
		Src:		srcIP,
		Dst:		dstIP,
	}

	for i := 0; i < rn; i++ {
		err := rawConn.WriteTo(wiph, wb, nil)
		if err != nil {
			log.Printf("error when writing RawConn in RscanSendUdpByRawConn(%v:%v->%v:%v): %v\n", srcIP, srcPort, dstIP, dstPort, err)
			return -1
		}
	}
	return 0
}

func retrieve_pfx24_as(pfx24 string)string{
	prefile, err := os.Open("./pfx24_info.input") 
    	if err!=nil {
		log.Fatalf("error when opening input file: %v\n", err)
    	}
	scanner := bufio.NewScanner(prefile) 
	buf := make([]byte, 0, 64*1024)
        scanner.Buffer(buf, 400*1024*1024)
	
    	for scanner.Scan() { 
		
		line := scanner.Text()
		fields := strings.Split(line, ",") // 211.106.174.0,211.104.0.0,14,4766
		if len(fields) < 4 { continue }
		if fields[0] == pfx24 { return fields[3]}
	}
	return ""
}



func myTracerouteCmd(target_pfx24, server string, as_path map[string][]string){
	
	cmd := exec.Command("traceroute","-q","1","-n", "-e","-m", "65", "-I", server)
	out, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	
	done := make(chan bool)
	scanner := bufio.NewScanner(out)
	go func() { 
		defer func() { done <- true }()
	
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			ip := fields[1]
			if ip == "*" { 
				as_path[server] = append(as_path[server], "*")
				continue
			}
			ipf := strings.Split(ip, ".")
			if len(ipf) < 4 { 
				continue
			}
			ipf[3] = "0"
			pfx24 := strings.Join(ipf, ".")
			asn := retrieve_pfx24_as(pfx24)
			if len(asn) == 0 {
			     	as_path[server] = append(as_path[server], pfx24)
				continue
			}
			as_path[server] = append(as_path[server], asn)
		}
	} ()
	err = cmd.Start()
	if err != nil {
		log.Fatalf("error when starting the command: %v\n", err)
	}
	<- done
	err = cmd.Wait()
	if err != nil {
		log.Fatalf("error when cmd.Wait(): %v\n", err)
	}

}

// The result contains 0: appliable but non-spoofable, 1: spoofable, -1: non-appliable, -2: errors before spoofing (non-appliable), -3: errors or weird cases during spoofing (appliable)
func RscanIdleHostThree(rscan_addr AddressSet, sip, sport string, port uint16, scan_type, domain string, spoof_ips []string, probes int) (int, []int) {
	      
	       rscanip := rscan_addr.ip 
	       ids := rscan_addr.ids
	       times := rscan_addr.times
	       v := rscan_addr.velocity
	       //rtt := rscan_addr.rtt
	       protocol := rscan_addr.protocol
	       c, rc := CreateRawConn(protocol) 
	       defer c.Close()
	       defer rc.Close()
	       
	       timeout := 1500 * time.Millisecond
	       // spoofing tests
	       temp_spoof_ips := []string{}
	       if spoof_ips[0] == "0.0.0.0" { 
			spoofedIP := GetNeighbour(rscanip) 
			temp_spoof_ips = append(temp_spoof_ips, spoofedIP.String())
		} else {
			temp_spoof_ips = spoof_ips
		}
	      
	        ip := temp_spoof_ips[0] // currently, just consider testing with one spoofed source address 
		     
		spoofedIP := net.ParseIP(ip).To4()
	        log.Println(rscanip, "using spoofing IP:", spoofedIP)
		id := -9999
		switch protocol {
		case "tcp":
			id = RscanGetIpidByTcp(rc, "", rscanip, port, timeout, scan_type)
		case "udp":
			id = RscanGetIpidByUdp(nil, "", rscanip, domain, port, timeout)
		case "icmp":
			id, _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout)
		}
		ids = append(ids, id)
		times = append(times, time.Now())
		if id <= 0 { return -3, ids}

		dstIP := net.ParseIP(rscanip).To4()
		num_sent := probes
		for i := 0; i<probes; i++ {
			
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			switch protocol{
			case "tcp":
				var ok int
				switch scan_type{
				case "tcp SYN connect":
					ok = SendTcpByRawConn(rc, spoofedIP, dstIP, localPort, port, "S", 0, 0, 1, nil) 
				case "tcp SYN/ACK":
					ok = SendTcpByRawConn(rc, spoofedIP, dstIP, localPort, port, "SA", 0, 0, 1, nil) 
				case "tcp ACK":
					ok = SendTcpByRawConn(rc, spoofedIP, dstIP, localPort, port, "A", 0, 0, 1, nil) 
				case "tcp FIN":
					ok = SendTcpByRawConn(rc, spoofedIP, dstIP, localPort, port, "F", 0, 0, 1, nil) 
				case "tcp SYN":
					ok = SendTcpByRawConn(rc, spoofedIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
				}
				if ok == -1 { num_sent--}
				
			case "udp":
				//txid := uint16(rand.Int()) & 0xffff
				//SendUdpByRawConn(rc, spoofedIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
				ok := RscanSendUdpByRawConn(rc, spoofedIP, dstIP, localPort, port, 1)
				if ok == -1 { num_sent--}				
			case "icmp":
				id := uint16(rand.Int()) & 0xffff
				seq := uint16(rand.Int()) & 0xffff
				ok := SendIcmpByRawConn(rc, spoofedIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				if ok == -1 { num_sent--}
			}
			RscanWriteToServant(sip, sport, "responses,"+protocol+","+strconv.Itoa(int(localPort)))
			time.Sleep(10*time.Millisecond) // avoid triggering ICMP rate-limiting
		}
		
		if num_sent == 0 { return -3, ids}
		probes = num_sent
		//var k int
		////k = rtt/4
		//k = 10
		//time.Sleep( time.Duration(k) * time.Millisecond) 
		//log.Printf("sleeping for %vms", (rtt/4))
		id = -9999
		switch protocol {
		case "tcp":
			id = RscanGetIpidByTcp(rc, "", rscanip, port, timeout, scan_type)
		case "udp":
			id = RscanGetIpidByUdp(nil, "", rscanip, domain, port, timeout)
		case "icmp":
			id, _ = RscanGetIpidByIcmp(rc, "", rscanip, timeout)
		}
		ids = append(ids, id)
		times = append(times, time.Now())
		log.Println("ids: ", rscanip, spoofedIP, ids)
		if id <= 0 { return -3, ids}
		new_ids, _ := filter_nega(ids, times)
		// update threshold when all of the IPID values observed are even: probes = 2*probes
		num_even := 0
		for _, id := range new_ids {
			if  (id % 2 == 0) {
				num_even++	
			}
		}
		if len(new_ids) == num_even {
			probes = 2*probes
		}
		
		if MyIpidSpoofable(rscanip, ids, times, probes, v) {
			
			return 1, ids
			
		} 
		
	return 0, ids
}

func RscanIdleHostUdp(rscanip string, port uint16, domain string) (int, []int){
	       c, rc := CreateRawConn("udp") 
	       defer c.Close()
	       defer rc.Close()
	       // set a suitable timeout
               //timeout := SetRecTimeout(rscanip, 0, protocol)
	       timeout := 1000 * time.Millisecond
	       spoofedIP := GetNeighbour(rscanip) // Attention: change spoofed IP address to the neighbor IP of the target telnet server
	       //spoofedIP := GetSpoofedIP(rscanip, domain)
	       log.Println(rscanip, "using spoofing IP:", spoofedIP)
	       ids := make([]int, 5, 5)
	       times := make([]time.Time, 5, 5)
	       normals := 4
	       for i:= 0; i<normals; i++ {
	    	   id := RscanGetIpidByUdp(nil, "", rscanip, domain, port, timeout)
	    	   time := time.Now()
		   if id <= 0 {return -9, ids}
		   
		   ids[i] = id
		   times[i] = time 
	    	}
	       
		var wg sync.WaitGroup
		probes := 10
		dstIP := net.ParseIP(rscanip).To4()
		txid := uint16(rand.Int()) & 0xffff	
		for i := 0; i<probes; i++ {
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			wg.Add(1)
			go func(localPort uint16) {
				defer wg.Done()
				SendUdpByRawConn(rc, spoofedIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
				
				
			}(localPort)		
		} 
		wg.Wait()
		ids[normals] = RscanGetIpidByUdp(nil, "", rscanip, domain, port, timeout)
		times[normals] = time.Now()
		if ids[normals] <= 0 {return -9, ids}
		
		
		if MyIpidSpoofable(rscanip, ids, times, probes, 0) {
			
			return 1, ids
			
		} 
	return 0, ids	
}

func IsResponsive(rscanip string) bool {
	timeout := 1500 * time.Millisecond
	id, _ := RscanGetIpidByIcmp(nil, "199.244.49.220", rscanip, timeout)
	if id < 0 { return false}
	return true
}

func IcmpLimitingRateCombinedTraffic(ip string, low_rate, high_rate int) (int,int) {
	
	sm := sync.Mutex{}

	localIP := GetLocalIP()
	spoofedIP := GetNeighbour(ip)
	//spoofedIP := net.ParseIP("199.244.49.220").To4()
	dstIP := net.ParseIP(ip).To4()

	num_spoofed := high_rate //per second
	num_normal := 1 // per second
	
	num_sent := 0
	num_received := 0
	prob_rate := num_spoofed + num_normal
	timeout := 1000 * time.Millisecond
	for s := 0; s < 5; s++ {	
		for i := 0; i < prob_rate; i++ {
			
			id := uint16(rand.Int()) & 0xffff
			seq := uint16(rand.Int()) & 0xffff
			
			if i< num_spoofed {
				ok := SendIcmpByRawConn(nil, spoofedIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				if ok == -1 {
					log.Printf("Error in testing icmp limiting rate: %v,%v", dstIP, prob_rate)
					continue
				}
				
			} else {
				ok := SendIcmpByRawConn(nil, localIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				if ok == -1 {
					log.Printf("Error in testing icmp limiting rate: %v,%v", dstIP, prob_rate)
					continue
				}
				num_sent++
				go func (id, seq uint16) {
					riph, _ := RscanRecvByRawConn(nil, dstIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout)
					if riph != nil { 
						sm.Lock()
						num_received++
						sm.Unlock()
					 }
				}(id, seq)
			}
			
			if i == high_rate-1 {
				time.Sleep(time.Duration(1.0/float64(high_rate)*1000)*time.Millisecond/2) 
			} else {
			
				time.Sleep(time.Duration(1.0/float64(high_rate)*1000)*time.Millisecond)
			}
		}
	}
	time.Sleep(5*time.Second)
	
	return num_sent, num_received
}

func RecvLimitingRate(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort, txid uint16, proto, flags, needle string, ack uint32, icmp []uint16, c int, res chan<-int, timeout time.Duration, sm *sync.Mutex) {
	if rawConn == nil {
		c, rc := CreateRawConn(proto)
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	
	rb := make([]byte, 1500) // the maximal capacity of ethenet link
	
	
	ddl := time.Now().Add(timeout)
	for {
		
		if time.Now().After(ddl) {
			sm.Lock()
			res <- -1
			sm.Unlock()
			return 
		}
		if err := rawConn.SetReadDeadline(ddl); err != nil {
			
			log.Printf("error when setting RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v) with a needle (%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, needle, err)
			continue
		}
	        //func (c *RawConn) ReadFrom(b []byte) (h *Header, p []byte, cm *ControlMessage, err error)
	 	
                riph, _, _, err := rawConn.ReadFrom(rb)
		
		if err != nil {
			//log.Printf("error when reading RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
			continue
		}
		
		if !riph.Src.Equal(srcIP) { continue }  // Uncommented this to test against the networks behind a NAT or firewall (there exists address rewriting.)
		if !riph.Dst.Equal(dstIP) { continue } // due to the multiple ip addresses 
		if proto == "tcp" && riph.Protocol != int(layers.IPProtocolTCP) { continue }
		if proto == "udp" && riph.Protocol != int(layers.IPProtocolUDP) { continue }
		if proto == "icmp" && riph.Protocol != int(layers.IPProtocolICMPv4) { continue }
		
		packet := gopacket.NewPacket(rb, layers.LayerTypeIPv4, gopacket.Default)
			
		if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
			
			ricmpl, ok := l.(*layers.ICMPv4)
		
			if !ok {
				log.Printf("error when parsing ICMP in RecvByRawConn(%v, %v->%v): %v\n", proto, srcIP, dstIP, err)
				continue
			}
			
			if uint16(ricmpl.TypeCode) == 0 { // icmp reply
				
				if ricmpl.Id == icmp[1] && ricmpl.Seq == icmp[2] { // 
					sm.Lock()
					res <- 1
					sm.Unlock()
					return
				}
			}
			continue
		}
		// riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil)
			
		if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		        
			rtcpl, ok := l.(*layers.TCP)
			
			if !ok {
				log.Printf("error when parsing TCP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
				continue
			}
			if uint16(rtcpl.DstPort) == dstPort {
				match := true
				if strings.Contains(flags, "S") && !rtcpl.SYN { match = false }
				if strings.Contains(flags, "A") && !rtcpl.ACK { match = false }    				
				if strings.Contains(flags, "F") && !rtcpl.FIN { match = false }
				if strings.Contains(flags, "R") && !rtcpl.RST { match = false }				
				if strings.Contains(flags, "P") && !rtcpl.PSH { match = false }
				if ack != 0 && rtcpl.Ack != ack { match = false }
				if strings.Contains(flags, "SA") && rtcpl.SYN && rtcpl.ACK { match = true } 
				if strings.Contains(flags, "RA") && rtcpl.RST && rtcpl.ACK { match = true }
				if strings.Contains(flags, "R") && rtcpl.RST{ match = true }
				if match {
					
					res <- 1
					return
				}
				
			}
		}

		if l := packet.Layer(layers.LayerTypeUDP); l != nil {
			rudpl, ok := l.(*layers.UDP)
			if !ok {
				log.Printf("error when parsing UDP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
				continue
			}
			if uint16(rudpl.DstPort) == dstPort  && uint16(rudpl.SrcPort) == srcPort{
				res <- 1
				return
					
			}
		}
	}
}

func SendIcmpRequest(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, icmp []uint16, rn, prob_rate int, payload []byte) int {
	if rawConn == nil {
		c, rc := CreateRawConn("icmp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
       
	wicmpl := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeCode(icmp[0]),
		Id: icmp[1],
		Seq: icmp[2], // see the structure of different types of ICMP messages, for echo request and reply contains id and seq; but for ICMP MTU message here should be unused and net-hop MTU 
	}

	sbuf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{ComputeChecksums:true}
	gopacket.SerializeLayers(sbuf, sopts,
		wicmpl,
		gopacket.Payload(payload),
	)
	wb := sbuf.Bytes()
	var ttl int
	if srcIP.String() == "8.8.8.8" { 
		ttl = 40
	} else {
		ttl = 64
	}
	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			0,
		FragOff:	0,
		TTL:		ttl, 
		Protocol:	int(layers.IPProtocolICMPv4),
		Checksum:	0,
		Src:		srcIP,
		Dst:		dstIP,
	}
	// measure the time shift
	T := 1.0/float64(prob_rate)*1000000000
	ave_shift := float64(0)
	if prob_rate > 1000 {
		sum := float64(0)
		for i := 0; i < 5; i++ {
			time0 := time.Now()
			time.Sleep(time.Duration(T)*time.Nanosecond)
			shift := float64(time.Now().Sub(time0).Nanoseconds()) - T
			sum += shift
		}
		ave_shift = sum/5
	}
	delay := time.Duration(T-ave_shift)*time.Nanosecond
	for i := 0; i < rn; i++ {
		
		go func(){
			err := rawConn.WriteTo(wiph, wb, nil)
			if err != nil {
				log.Printf("error when writing RawConn in SendIcmpByRawConn(%v->%v): %v\n", srcIP, dstIP, err)
			}
		}()
		time.Sleep(delay)
	}
	return 0
}
//compensate for delays by sleeping for shorter intervals.
func compute_delay(prob_rate int) float64{
	T := 1.0/float64(prob_rate)*1000000 //Microsecond
	ave_shift := float64(0)
	if prob_rate >= 1000 {
		sum := float64(0)
		for i := 0; i < 5; i++ {
			time0 := time.Now()
			//time.Sleep(time.Duration(T)*time.Microsecond)
			b := <-time.After(time.Duration(T)*time.Microsecond)
			shift := float64(b.Sub(time0).Nanoseconds())/1000.0 - T
			sum += shift
		}
		ave_shift = sum/5
	}
	d := T-ave_shift
	if d <= 0 {
		d = T // in the large delay it is impossible to compensate
	}
	return d
}

func BurstClearing(sip, ip, proto string, port uint16, dur, def_rate int){
	var srcIP net.IP
	if len(sip) == 0 {
		srcIP = GetLocalIP()
	} else {
        	srcIP = net.ParseIP(sip).To4()
	}
	dstIP := net.ParseIP(ip).To4()
	def_num := 1 * def_rate 
	def_d := compute_delay(def_rate)
	def_sleep := time.Duration(def_d)*time.Microsecond
	id := uint16(rand.Int()) & 0xffff
	seq := uint16(0)
	for i := 0; i < def_num; i++ { // cleaning the burst setting to avoid the interference of burst packets, for example, when the threshold is small but the burst is very large: th = 1 and burst packets = 20, then it will prevent from the identification of the threshold. 
		go func(){
			SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
			seq++
		}()
		<-time.After(def_sleep)
	}

}

func LimitingRateTestIPv4(sip, ip, proto string, port uint16, dur, def_rate, prob_rate int, domain string) float64 {
	var wg sync.WaitGroup
	var srcIP net.IP
	if len(sip) == 0 {
		srcIP = GetLocalIP()
	} else {
        	srcIP = net.ParseIP(sip).To4()
	}
	dstIP := net.ParseIP(ip).To4()
	def_num := 100
	num := dur*prob_rate
	var def_d float64
	def_d = 1
	def_sleep := time.Duration(def_d)*time.Microsecond
	d := compute_delay(prob_rate)
	sleep := time.Duration(d)*time.Microsecond
	
	//delay = time.Duration(1.0/float64(prob_rate)*1000000)*time.Microsecond
	
	T := time.Duration(dur*1000) //sleeping two seconds
	timeout := T*time.Millisecond 
	sum := 0
	
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} 
	listen := true
	switch proto {
	case "icmp":
		
		typeCode := uint16(0)
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(0)
		go RecvLimitingRatePcap01(dstIP, srcIP, 0, nil, 0, "icmp", "", "", 0, []uint16{typeCode, id, seq}, timeout, &sum, &wg, handle, &listen)	
		//time0 := time.Now()
		for i := 0; i < def_num; i++ { // cleaning the burst setting to avoid the interference of burst packets, for example, when the threshold is small but the burst is very large: th = 1 and burst packets = 20, then it will prevent from the identification of the threshold. 
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}()
			<-time.After(def_sleep)
		}
		//listen = false
		id = uint16(rand.Int()) & 0xffff + 1
		wg.Add(1)
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}()
		}
		
	
	case "tcp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		for i := 0; i < def_num; i++ { // cleaning the burst setting to avoid the interference of burst packets, for example, when the threshold is small but the burst is very large: th = 1 and burst packets = 20, then it will prevent from the identification of the threshold within a small time period. In oder to reduce time consumption we induce an extra second to clean the existing tokens in the bucket before measurements. 
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendTcpByRawConn(nil, srcIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}()
			<-time.After(def_sleep)
		}
		
		localPort = 10000 + (uint16(rand.Int()) & 0xffff) % 55535 + 1
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP, port, &localPort, 0, "tcp", "SA,R,RA", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		//listen = true
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendTcpByRawConn(nil, srcIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}()
			
		}
		
		
	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		for i := 0; i < def_num; i++ { 
			wg.Add(1)
			go func(){
				defer wg.Done()
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, srcIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
			}()
			<-time.After(def_sleep)
		}
		localPort = 10000 + (uint16(rand.Int()) & 0xffff) % 55535 + 1
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP, port, &localPort, 0, "udp", "", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		
		listen = true
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, srcIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
				//riph, _ = RecvByRawConn(nil, dstIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
			}()
			
		}

		}
	wg.Wait()
	lr := math.Round((1-float64(sum)/float64(def_num))* 1000)/1000
	
	return lr
}


func LimitingRateTestIPV3(sip, ip, proto string, port uint16, dur, def_rate, prob_rate int, domain string) float64 {
	var wg sync.WaitGroup
	var srcIP net.IP
	if len(sip) == 0 {
		srcIP = GetLocalIP()
	} else {
        	srcIP = net.ParseIP(sip).To4()
	}
	dstIP := net.ParseIP(ip).To4()
	def_num := 1 * def_rate // 10000
	num := dur*prob_rate
	var def_d float64
	if def_rate == 10000 {
		def_d = 1
	} else {
		def_d = compute_delay(def_rate)
	}
	def_sleep := time.Duration(def_d)*time.Microsecond
	d := compute_delay(prob_rate)
	sleep := time.Duration(d)*time.Microsecond
	
	//delay = time.Duration(1.0/float64(prob_rate)*1000000)*time.Microsecond
	
	T := time.Duration((dur+2)*1000) //sleeping two seconds
	timeout := T*time.Millisecond 
	sum := 0
	
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} 
	listen := true
	switch proto {
	case "icmp":
		
		typeCode := uint16(0)
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(0)

		//time0 := time.Now()
		for i := 0; i < def_num; i++ { // cleaning the burst setting to avoid the interference of burst packets, for example, when the threshold is small but the burst is very large: th = 1 and burst packets = 20, then it will prevent from the identification of the threshold. 
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}()
			<-time.After(def_sleep)
		}
		//time1 := time.Now()
		//fmt.Println(float64(time1.Sub(time0).Nanoseconds())/1000.0)
		id = uint16(rand.Int()) & 0xffff + 1
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP, 0, nil, 0, "icmp", "", "", 0, []*uint16{&typeCode, &id, &seq}, timeout, &sum, &wg, handle, &listen)
		
		//listen = true
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}()
		}
		
	
	case "tcp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		for i := 0; i < def_num; i++ { // cleaning the burst setting to avoid the interference of burst packets, for example, when the threshold is small but the burst is very large: th = 1 and burst packets = 20, then it will prevent from the identification of the threshold within a small time period. In oder to reduce time consumption we induce an extra second to clean the existing tokens in the bucket before measurements. 
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendTcpByRawConn(nil, srcIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}()
			<-time.After(def_sleep)
		}
		
		localPort = 10000 + (uint16(rand.Int()) & 0xffff) % 55535 + 1
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP, port, &localPort, 0, "tcp", "SA,R,RA", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		//listen = true
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				SendTcpByRawConn(nil, srcIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}()
			
		}
		
		
	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		for i := 0; i < def_num; i++ { 
			wg.Add(1)
			go func(){
				defer wg.Done()
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, srcIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
			}()
			<-time.After(def_sleep)
		}
		localPort = 10000 + (uint16(rand.Int()) & 0xffff) % 55535 + 1
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP, port, &localPort, 0, "udp", "", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		
		listen = true
		for i := 0; i < num; i++ {
			<-time.After(sleep)
			wg.Add(1)
			go func(){
				defer wg.Done()
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, srcIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
				//riph, _ = RecvByRawConn(nil, dstIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
			}()
			
		}

		}
	wg.Wait()
	lr := math.Round((1-float64(sum)/float64(num))* 1000)/1000
	
	return lr
}

func LimitingRateTestIPV2(srcIP, ip, proto string, port uint16, dur, prob_rate int, sleep time.Duration, domain string) (float64, time.Duration) {
	var wg sync.WaitGroup
	var localIP net.IP
	if len(srcIP) == 0 {
		localIP = GetLocalIP()
	} else {
        	localIP = net.ParseIP(srcIP).To4()
	}
	dstIP := net.ParseIP(ip).To4()
	num := dur*prob_rate
	if sleep == 0 {
		d := compute_delay(prob_rate)
		sleep = time.Duration(d)*time.Microsecond
		//fmt.Println(sleep)
	}
	//delay = time.Duration(1.0/float64(prob_rate)*1000000)*time.Microsecond
	
	T := time.Duration(dur) // dur+2
	timeout := T*time.Second 
	sum := 0
	
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} 
	listen := true
	switch proto {
	case "icmp":
		typeCode := uint16(0)
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(0)
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, localIP, 0, nil, 0, "icmp", "", "", 0, []*uint16{&typeCode, &id, &seq}, timeout, &sum, &wg, handle, &listen)
		
		for i := 0; i < num; i++ {
			go func(){
				SendIcmpByRawConn(nil, localIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}()
			<-time.After(sleep)
		}
			
			
			

	case "tcp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, localIP, port, &localPort, 0, "tcp", "SA,R,RA", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		//time.Sleep(1*time.Second)
		for i := 0; i < num; i++ {
			go func(){
				SendTcpByRawConn(nil, localIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}()
			<-time.After(sleep)
		}
			
	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, localIP, port, &localPort, 0, "udp", "", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		for i := 0; i < num; i++ {
			go func(){
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, localIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
				//riph, _ = RecvByRawConn(nil, dstIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
			}()
			<-time.After(sleep)
		}

		}
	wg.Wait()
	lr := math.Round((1-float64(sum)/float64(num))* 1000)/1000
	
	return lr, sleep
}



func LimitingRateTest(ip, proto string, port uint16, domain string) (float64, int) {
	var wg sync.WaitGroup
	localIP := GetLocalIP()
	dstIP := net.ParseIP(ip).To4()
	num := 10
	sleep := time.Duration(1000)*time.Microsecond
	timeout := time.Duration(1000)*time.Millisecond
	listen := true
	handle, err := pcap.OpenLive("ens160", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	sum := 0
	switch proto {
	case "icmp":
		typeCode := uint16(0)
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(0)
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, localIP, 0, nil, 0, "icmp", "", "", 0, []*uint16{&typeCode, &id, &seq}, timeout, &sum, &wg, handle, &listen)
		
		for i := 0; i < num; i++ {
			
			SendIcmpByRawConn(nil, localIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
			seq++
			
			<-time.After(sleep)
		}
			
			
			

	case "tcp":
		wg.Add(1)
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		go RecvLimitingRatePcap(dstIP, localIP, port, &localPort, 0, "tcp", "SA", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		//time.Sleep(1*time.Second)
		for i := 0; i < num; i++ {
			localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
			seq := uint32(rand.Int()) & 0xffffffff
			SendTcpByRawConn(nil, localIP, dstIP, localPort, port, "S", seq, 0, 1, nil)
			<-time.After(sleep)
		}
			
	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, localIP, port, &localPort, 0, "udp", "", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		for i := 0; i < num; i++ {
			txid := uint16(rand.Int()) & 0xffff
			SendUdpByRawConn(nil, localIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
			//riph, _ = RecvByRawConn(nil, dstIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
			<-time.After(sleep)
		}

		}
	wg.Wait()
	lr := 1-float64(sum)/float64(num)
	
	return lr, sum
}


func RecvLimitingRatePcap01(srcIP, dstIP net.IP, srcPort uint16, dstPort *uint16, txid uint16, proto, flags, needle string, ack uint32, icmp []uint16, timeout time.Duration, p *int, wg *sync.WaitGroup, handle *pcap.Handle, listen *bool) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ddl := time.Now().Add(timeout)
	for packet := range packetSource.Packets() {
		if !(*listen) { continue }
		r := HandlePacket01(packet,srcIP, dstIP, srcPort, dstPort, txid, proto, flags, needle, ack, icmp)
		if r == 1 {
			*p++
		}
		if time.Now().After(ddl) {
			break
		}
	}
	
}

func HandlePacket01(packet gopacket.Packet, srcIP, dstIP net.IP, srcPort uint16, dstPort *uint16, txid uint16, proto, flags, needle string, ack uint32, icmp []uint16) int{
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
                ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			log.Printf("error when parsing IP in RawConn(%v, %v->%v)\n", proto, srcIP, dstIP)
			return -1
		}
                if !ip.SrcIP.Equal(srcIP) { return -1}
		if !ip.DstIP.Equal(dstIP) { return -1}
		if proto == "tcp" && ip.Protocol != layers.IPProtocolTCP { return -1 }
		if proto == "udp" && ip.Protocol != layers.IPProtocolUDP { return -1 }
		if proto == "icmp" && ip.Protocol != layers.IPProtocolICMPv4 { return -1}
	}
	if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {

		ricmpl, ok := l.(*layers.ICMPv4)

		if !ok {
			log.Printf("error when parsing ICMP in RawConn(%v, %v->%v)\n", proto, srcIP, dstIP)
			return -1
		}
		
		if uint16(ricmpl.TypeCode) == icmp[0] { // icmp reply
			if ricmpl.Id == icmp[1] {  // ricmpl.Seq == icmp[2]
				//fmt.Println("icmp")
				return 1
			}
		}
	}
	
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		        
		rtcpl, ok := l.(*layers.TCP)
		
		if !ok {
			log.Printf("error when parsing TCP in RecvByRawConn(%v, %v:%v->%v:%v)\n", proto, srcIP, srcPort, dstIP, dstPort)
			return -1
		}
		if uint16(rtcpl.DstPort) == *dstPort && uint16(rtcpl.SrcPort) == srcPort {
			match := false
			if strings.Contains(flags, "SA") && rtcpl.SYN && rtcpl.ACK { 
				match = true 
			} 
			if strings.Contains(flags, "RA") && rtcpl.RST && rtcpl.ACK { match = true }
			if strings.Contains(flags, "R") && rtcpl.RST{ match = true }
			if match {
				//fmt.Println("tcp")
				return 1
			}
			
		}
	}

	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		rudpl, ok := l.(*layers.UDP)
		if !ok {
			log.Printf("error when parsing UDP in RecvByRawConn(%v, %v:%v->%v:%v)", proto, srcIP, srcPort, dstIP, dstPort)
			return -1
		}
		if uint16(rudpl.DstPort) == *dstPort && uint16(rudpl.SrcPort) == srcPort {
			if l := packet.Layer(layers.LayerTypeDNS); l!=nil {
				rdnsl, ok := l.(*layers.DNS)
				if !ok {
					log.Printf("error when parsing DNS in RecvByRawConn(%v, %v:%v->%v:%v)\n", proto, srcIP, srcPort, dstIP, dstPort)
					return -1
				}
				if rdnsl.QR { //rdnsl.ID == txid
					
					return 1
				}
			}
		}
	}

	return -1
}

func HandlePacket(packet gopacket.Packet, srcIP, dstIP net.IP, srcPort uint16, dstPort *uint16, txid uint16, proto, flags, needle string, ack uint32, icmp []*uint16) int{
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
                ip, ok := ipLayer.(*layers.IPv4)
		if !ok {
			log.Printf("error when parsing IP in RawConn(%v, %v->%v)\n", proto, srcIP, dstIP)
			return -1
		}
                if !ip.SrcIP.Equal(srcIP) { return -1}
		if !ip.DstIP.Equal(dstIP) { return -1}
		if proto == "tcp" && ip.Protocol != layers.IPProtocolTCP { return -1 }
		if proto == "udp" && ip.Protocol != layers.IPProtocolUDP { return -1 }
		if proto == "icmp" && ip.Protocol != layers.IPProtocolICMPv4 { return -1}
	}
	if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {

		ricmpl, ok := l.(*layers.ICMPv4)

		if !ok {
			log.Printf("error when parsing ICMP in RawConn(%v, %v->%v)\n", proto, srcIP, dstIP)
			return -1
		}
		
		if uint16(ricmpl.TypeCode) == *icmp[0] { // icmp reply
			if ricmpl.Id == *icmp[1] {  // ricmpl.Seq == icmp[2]
				//fmt.Println("icmp")
				return 1
			}
		}
	}
	
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		        
		rtcpl, ok := l.(*layers.TCP)
		
		if !ok {
			log.Printf("error when parsing TCP in RecvByRawConn(%v, %v:%v->%v:%v)\n", proto, srcIP, srcPort, dstIP, dstPort)
			return -1
		}
		if uint16(rtcpl.SrcPort) == srcPort {
			match := false
			if strings.Contains(flags, "SA") && !rtcpl.FIN && !rtcpl.RST && !rtcpl.PSH && rtcpl.ACK {match = true} // SA or A
			if strings.Contains(flags, "R") && rtcpl.RST{ match = true }
			if match {
				//fmt.Println("tcp")
				return 1
			}
			
		}
	}

	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		rudpl, ok := l.(*layers.UDP)
		if !ok {
			log.Printf("error when parsing UDP in RecvByRawConn(%v, %v:%v->%v:%v)", proto, srcIP, srcPort, dstIP, dstPort)
			return -1
		}
		if uint16(rudpl.DstPort) == *dstPort && uint16(rudpl.SrcPort) == srcPort {
			if l := packet.Layer(layers.LayerTypeDNS); l!=nil {
				rdnsl, ok := l.(*layers.DNS)
				if !ok {
					log.Printf("error when parsing DNS in RecvByRawConn(%v, %v:%v->%v:%v)\n", proto, srcIP, srcPort, dstIP, dstPort)
					return -1
				}
				if rdnsl.QR { //rdnsl.ID == txid
					
					return 1
				}
			}
		}
	}

	return -1
}

func RecvLimitingRatePcap(srcIP, dstIP net.IP, srcPort uint16, dstPort *uint16, txid uint16, proto, flags, needle string, ack uint32, icmp []*uint16, timeout time.Duration, p *int, wg *sync.WaitGroup, handle *pcap.Handle, listen *bool) {
	defer wg.Done()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ddl := time.Now().Add(timeout)
	for packet := range packetSource.Packets() {
		if !(*listen) { continue }
		r := HandlePacket(packet,srcIP, dstIP, srcPort, dstPort, txid, proto, flags, needle, ack, icmp)
		if r == 1 {
			*p++
		}
		if time.Now().After(ddl) {
			break
		}
	}
	
}




func CombinedTraffic(sip, sip0, sip1, ip, proto string, port uint16, dur, r_low, r_high int, domain string) float64 {
	
	var localIP net.IP
	srcIP := net.ParseIP(sip).To4()
        srcIP0 := net.ParseIP(sip0).To4()
	srcIP1 := net.ParseIP(sip1).To4()

	dstIP := net.ParseIP(ip).To4()
	num := dur * 1000
	num0 := int(math.Floor(1/(2*float64(dur)) * float64(r_low))) // 2
	num1 := int(math.Floor(1/(2*float64(dur)) * float64(r_high))) // 9
	//num := num0 + num1
	var wg sync.WaitGroup
	d := compute_delay(1000)
	d0 := compute_delay(r_low)
	d1 := compute_delay(r_high)
	sleep := time.Duration(d)*time.Microsecond
	sleep0 := time.Duration(d0)*time.Microsecond
	sleep1 := time.Duration(d1)*time.Microsecond
	fmt.Println(sleep, sleep0, sleep1)
	
	//delay = time.Duration(1.0/float64(prob_rate)*1000000)*time.Microsecond
	
	T := time.Duration(dur+1)
	timeout := T*time.Second 
	
	sum := 0
	
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} 
	listen := true
	switch proto {
	case "icmp":
		typeCode := uint16(0)
		id := uint16(rand.Int()) & 0xffff
		seq := uint16(0)
		for i := 0; i < num; i++ {
			go func(wg *sync.WaitGroup){
				SendIcmpByRawConn(nil, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil)
				seq++
			}(&wg)
			<-time.After(sleep)
		}
		wg.Add(1)
		go RecvLimitingRatePcap(dstIP, srcIP1, 0, nil, 0, "icmp", "", "", 0, []*uint16{&typeCode, &id, &seq}, timeout, &sum, &wg, handle, &listen)
		for j := 0; j <1; j++ {
			for i := 0; i < num0; i++ {
				go func(wg *sync.WaitGroup){
					SendIcmpByRawConn(nil, srcIP0, dstIP, []uint16{8*256, id, seq}, 1, nil)
					seq++
				}(&wg)
				<-time.After(sleep0)
			}
			

			for i := 0; i < num1; i++ {
				go func(wg *sync.WaitGroup){
					SendIcmpByRawConn(nil, srcIP1, dstIP, []uint16{8*256, id, seq}, 1, nil)
					seq++
				}(&wg)
				<-time.After(sleep1)
			}
		}

	case "tcp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		//wg.Add(1)
		//go RecvLimitingRatePcap(dstIP, srcIP0, port, localPort, 0, "tcp", "SA,R,RA", "", 0, nil, timeout, &sum0, &wg, handle)
		
		for i := 0; i < num0; i++ {
			go func(wg *sync.WaitGroup){
				SendTcpByRawConn(nil, localIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}(&wg)
			time.Sleep(sleep0)
		}
		go RecvLimitingRatePcap(dstIP, srcIP1, port, &localPort, 0, "tcp", "SA,R,RA", "", 0, nil, timeout, &sum, &wg, handle, &listen)
		
		for i := 0; i < num1; i++ {
			go func(wg *sync.WaitGroup){
				SendTcpByRawConn(nil, localIP, dstIP, localPort, port, "S", 0, 0, 1, nil)
			}(&wg)
			time.Sleep(sleep1)
		}

	case "udp":
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		txid := uint16(rand.Int()) & 0xffff
		SendUdpByRawConn(nil, localIP, dstIP, localPort, port, txid, 65535, domain, "A", 1)
			//riph, _ = RecvByRawConn(nil, dstIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
		}
	wg.Wait()
	fmt.Println("sum: ", sum)
	lr := math.Round((1-float64(sum)/float64(num1))* 1000)/1000
	
	return lr
}

func IcmpLimitingRateTest(cidr, protocol string, prob_rate int) map[string]int {
	packets_sent := make(map[string]int)
	localIP := GetLocalIP()
	timeout := 5*time.Second
	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
	_,err := scanner.AddCIDR(cidr)
	if err != nil {
		log.Printf("Error in parsing cidr: %v,%v,%v", cidr, protocol, prob_rate)
	}
	sm := sync.Mutex{}
	var wg sync.WaitGroup

	for _, extIP := range scanner.ips {
		wg.Add(1)
		go func(extIP net.IP) {
			defer wg.Done()
			if !IsResponsive(extIP.String()) {return}
			for i := 0; i < 30*prob_rate; i++ {
				go func() {
					id := uint16(rand.Int()) & 0xffff
					seq := uint16(rand.Int()) & 0xffff
					
					ok := SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
					if ok == -1 {
						log.Printf("Error in testing icmp limiting rate: %v,%v,%v", extIP, protocol, prob_rate)
						return
					}
					sm.Lock()
					packets_sent[extIP.String()]++
					sm.Unlock()
					
				}() 
				
				time.Sleep(time.Duration(1.0/float64(prob_rate)*1000)*time.Millisecond)
			}
		}(extIP)
	}

	wg.Wait()
	return packets_sent
}

func RscanIpidTestChan(cidr, sip, sport string, port uint16, scan_type, protocol, domain string, spoof_ips []string, probes, v_thres int) (int, []int, []string, map[string][]string) { 
	codeset := []int{}
        as_path := make(map[string][]string)
        timeout := 5*time.Second
     	tserver := make([]string, 0) 
	targetChan := make(chan AddressSet, 256)
     	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
     	_,err := scanner.AddCIDR(cidr)
     	if err != nil {  
	   log.Println("error in parsing cidr:", cidr, err) 
     	   return -2, codeset, tserver, as_path
     	}

	scanner.Scan(sip, sport, port, scan_type, domain, v_thres, targetChan) // the set of idle hosts identified but regardless whether the sanned port on the host  								     //is open or not, and we only care about whether there is a response from the scanned 								     //host.
	// here addrset contains the scanning results all of hosts within the IPv4/24 network 
	num := 0
	for addr := range targetChan {
	       if (!reflect.DeepEqual(AddressSet{},addr)) {
			code, _ := RscanIdleHostThree(addr, sip, sport, port, scan_type, domain, spoof_ips, probes)
			tserver = append(tserver, addr.ip)
			codeset = append(codeset, code) // code: 0, 1, -3
		}
		num++
		if num == cap(targetChan) {
			break
		}		 
	}
	if len(tserver) == 0 {
		return -1, codeset, tserver, as_path
	}
	maxc := codeset[0]
	for _, c := range codeset {
		if c > maxc {
			maxc = c
		}
	}
	return maxc, codeset, tserver, as_path
}


// -2: errors during tests, -1: non-appliable, 0: appliable but non-spoofable, 1: spoofable
// -1: non-global IPID, failure in scanning telnet hosts: no response to TCP SYN received from the test server (because non-alive hosts, port filtering or connection blocked by firewall, etc.); no suitable idle hosts identified, etc. 
// scan type: TCP SYN connect; TCP SYN/ACK; TCP ACK; TCP FIN
func RscanIpidTest(cidr, sip, sport string, port uint16, scan_type, protocol, domain string, spoof_ips []string, probes, v_thres int) (int, []int, []string, map[string][]string) { 
	codeset := []int{}
        as_path := make(map[string][]string)
        timeout := 5*time.Second
     	tserver := make([]string, 0) 
	targetChan := make(chan AddressSet, 256)
     	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
     	_,err := scanner.AddCIDR(cidr)
     	if err != nil {  
	   log.Println("error in parsing cidr:", cidr, err) 
     	   return -2, codeset, tserver, as_path
     	}

	addrset := scanner.Scan(sip, sport, port, scan_type, domain, v_thres, targetChan) // the set of idle hosts identified but regardless whether the sanned port on the host  								     //is open or not, and we only care about whether there is a response from the scanned 								     //host.
	// here addrset contains the scanning results all of hosts within the IPv4/24 network 
	if len(addrset) == 0 {		
		return -1, codeset, tserver, as_path
	}

	 for _, addr := range addrset {
	       //if len(as_path) == 0 || len(as_path) > 64 {
	       //	as_path_ = make(map[string][]string)
	       //	myTracerouteCmd(cidr, addr.ip, as_path)
	       //}
	       code, _ := RscanIdleHostThree(addr, sip, sport, port, scan_type, domain, spoof_ips, probes)
	       tserver = append(tserver, addr.ip)
	       codeset = append(codeset, code) // code: 0, 1, -3
	 }
	
	maxc := codeset[0]
	for _, c := range codeset {
		if c > maxc {
			maxc = c
		}
	}
	return maxc, codeset, tserver, as_path
}

func RscanIpidTestWeirdCases(cidr, sip, sport string, port uint16, scan_type, protocol, domain string, spoof_ips []string, probes int) (int, []int, map[string][]string) { 
	codeset := []int{}
        as_path := make(map[string][]string) // Every server to be tested has a path. 
        timeout := 5*time.Second
     	scanner := NewScanner(WithTimeout(timeout), WithProtocol(protocol)) 
     	_,err := scanner.AddCIDR(cidr)
     	if err != nil {  
	   log.Println("error in parsing cidr:", cidr, err) 
     	   return -2, codeset, as_path
     	}

	addrset := scanner.Scan(sip, sport, port, scan_type, domain, 50, nil) // the set of idle hosts identified but regardless whether the sanned port on the host  								     //is open or not, and we only care about whether there is a response from the scanned 								     //host.
	// here addrset contains the scanning results all of hosts within the IPv4/24 network 
	if len(addrset) == 0 {		
		return -1, codeset, as_path
	}

	// identify the hosts that can be tested using the modified IPID technique, and then filter the hosts that are too busy...
	newAddrset := []AddressSet{}
	for _, addr := range addrset {
	       
	       ids := addr.ids
	       if IsIdle(ids) {
			newAddrset = append(newAddrset, addr)
		} else {
			continue
		}
		 
	}
	

	 if len(newAddrset) == 0 {
		return -1, codeset, as_path // non-applicable
	 }
	 
	 for _, addr := range newAddrset {
	       
	       as_path[addr.ip] = []string{}
	       myTracerouteCmd(cidr, addr.ip, as_path)
	       log.Println("AS path before spoofing:", cidr, addr.ip, as_path[addr.ip])
	       code, ids := RscanIdleHostThree(addr, sip, sport, port, scan_type, domain, spoof_ips, probes)
	       
	       codeset = append(codeset, code) // code: 0, 1, -3
	       if code == -3 {
			log.Println("Idle hosts after spoofing in case code is -3:", cidr, addr, ids)
			as_path[addr.ip] = []string{}
	       		myTracerouteCmd(cidr, addr.ip, as_path)
			log.Println("AS path after spoofing in case code is -3:", cidr, addr.ip, as_path[addr.ip])
	       }
	 }

	maxc := codeset[0]
	for _, c := range codeset {
		if c > maxc {
			maxc = c
		}
	}
	return maxc, codeset, as_path
}

func RscanGetIpidByIcmp(rawConn *ipv4.RawConn, srcIP, ip string, timeout time.Duration) (int, float64) {
	if rawConn == nil {
		c, rc := CreateRawConn("icmp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	var localIP net.IP
	if len(srcIP) == 0 {
		localIP = GetLocalIP()
	} else {
        	localIP = net.ParseIP(srcIP).To4()
	}
	extIP := net.ParseIP(ip).To4()
	id := uint16(rand.Int()) & 0xffff
	seq := uint16(rand.Int()) & 0xffff

	// ICMP TypeCode = (8, 0) = 8 * 256 + 0 = Echo
	ok := SendIcmpByRawConn(rawConn, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
	if ok == -1 { return -1, 0}
	time0 := time.Now()
	// ICMP TypeCode = (0, 0) = 0 * 256 + 0 = Echo Reply
	riph, _ := RscanRecvByRawConn(rawConn, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq}, timeout) // timeout=500ms
	if riph == nil { return -1, 0}
	time1 := time.Now()
	dur := float64(time1.Sub(time0).Nanoseconds())/1000000.0 // ms
	return riph.ID, dur
}

func TcpSynScan(rawConn *ipv4.RawConn, localIP, remoteIP net.IP, port, localPort uint16, timeout time.Duration) int {
	ok := SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "S", 0, 0, 1, nil)
	if ok == -1 { 
	     return -1
	}
	
	riph, _:= RscanRecvByRawConn(rawConn, remoteIP, localIP, port, localPort, 0, "tcp", "SA,RA,R", "", 0, nil, timeout)
	
	if riph == nil { 
	     return -1 
	}
	// Without sending an ACK to complete the handshake in case receiving a S/A packet as the response 
	return riph.ID 
}


func TcpSynConnectScan(rawConn *ipv4.RawConn, localIP, remoteIP net.IP, port, localPort uint16, timeout time.Duration) int {
	ok := SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "S", 0, 0, 1, nil)
	if ok == -1 { 
	     return -1
	}
	
	riph, rpkt:= RscanRecvByRawConn(rawConn, remoteIP, localIP, port, localPort, 0, "tcp", "SA,RA,R", "", 0, nil, timeout)
	
	if riph == nil { 
	     return -1 
	}
	rtcpl, _ := rpkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if rtcpl.SYN && rtcpl.ACK {
		ack := rtcpl.Seq + 1
		ok = SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "A", 1, ack, 1, nil)
		if ok == -1 { 
		      return -1 
		}
	}
	return riph.ID 
}

func TcpSynAckScan(rawConn *ipv4.RawConn, localIP, remoteIP net.IP, port, localPort uint16, timeout time.Duration) int {
	ok := SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "SA", 0, 0, 1, nil)
	if ok == -1 { 
	     return -1
	}
	
	riph, _:= RscanRecvByRawConn(rawConn, remoteIP, localIP, port, localPort, 0, "tcp", "RA,R", "", 0, nil, timeout)
	
	if riph == nil { 
	     return -1 
	}
	
	return riph.ID 
}

func TcpAckScan(rawConn *ipv4.RawConn, localIP, remoteIP net.IP, port, localPort uint16, timeout time.Duration) int {
	ok := SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "A", 0, 0, 1, nil)
	if ok == -1 { 
	     return -1
	}
	
	riph, _:= RscanRecvByRawConn(rawConn, remoteIP, localIP, port, localPort, 0, "tcp", "R", "", 0, nil, timeout)
	
	if riph == nil { 
	     return -1 
	}
	
	return riph.ID 
}

func TcpFinScan(rawConn *ipv4.RawConn, localIP, remoteIP net.IP, port, localPort uint16, timeout time.Duration) int {
	ok := SendTcpByRawConn(rawConn, localIP, remoteIP, localPort, port, "F", 0, 0, 1, nil)
	if ok == -1 { 
	     return -1
	}
	
	riph, _:= RscanRecvByRawConn(rawConn, remoteIP, localIP, port, localPort, 0, "tcp", "RA,R", "", 0, nil, timeout)
	
	if riph == nil { 
	     return -1 
	}
	
	return riph.ID 
}


// My test
func RscanGetIpidByTcp(rawConn *ipv4.RawConn, srcIP, ip string, port uint16, timeout time.Duration, scan_type string) int {
	if rawConn == nil {
		c, rc := CreateRawConn("tcp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	var id int
	var localIP net.IP
	if len(srcIP) == 0 {
		localIP = GetLocalIP()
	} else {
        	localIP = net.ParseIP(srcIP).To4()
	}
	remoteIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	switch scan_type {
	case "tcp SYN connect":
		id = TcpSynConnectScan(rawConn, localIP, remoteIP, port, localPort, timeout)
	case "tcp SYN/ACK":
		id = TcpSynAckScan(rawConn, localIP, remoteIP, port, localPort, timeout)
        case "tcp ACK":
		id = TcpAckScan(rawConn, localIP, remoteIP, port, localPort, timeout)
	case "tcp FIN":
		id = TcpFinScan(rawConn, localIP, remoteIP, port, localPort, timeout)
	case "tcp SYN":
		id = TcpSynScan(rawConn, localIP, remoteIP, port, localPort, timeout)
	}
		
	return id
}

func RscanSendIpidByUdp(srcIP, ip net.IP, port uint16, timeout time.Duration) (int, *ipv4.Header) {
	
	localIP := srcIP
	dialer := &net.Dialer{
    		LocalAddr: &net.UDPAddr{
        	IP:   localIP,
        	
    		},
	}
	
	p := strconv.Itoa(int(port))
	conn, err := dialer.Dial("udp", ip.String()+":"+p) 
	
	if err!=nil {

		log.Fatalf("error when dialing a network for %v: %v\n", "udp", err)
	} 
	defer conn.Close()
	
	m := "smap!helloworld"                                            
     	_, err = conn.Write([]byte(m+"\n"))
	if err != nil {
		return -1, nil
	}
	
	remoteIP := ip
	needle := "udp"
	riph, _ := RscanRecvByRawConn(nil, remoteIP, localIP, 0, 0, 0, "icmp", "", needle, 0, []uint16{771, 0, 0}, timeout) 

	//localAddr := strings.Split(conn.LocalAddr().String(), ":")
	//localPort, _ := strconv.Atoi(localAddr[1])
	//riph, _ := RscanRecvByRawConn(nil, remoteIP, localIP, port, uint16(localPort), 0, "udp", "", "", 0, nil, timeout)
	return 0, riph
}

func RscanGetIpidByUdp(rawConn *ipv4.RawConn, srcIP, ip, domain string, port uint16, timeout time.Duration) int {
	var localIP net.IP
	if len(srcIP) == 0 {
		localIP = GetLocalIP()
	} else {
        	localIP = net.ParseIP(srcIP).To4()
	}

 	dialer := &net.Dialer{
    		LocalAddr: &net.UDPAddr{
        	IP:   localIP,
        	
    		},
	}
	
	p := strconv.Itoa(int(port))
	conn, err := dialer.Dial("udp", ip+":"+p) 
	
	if err!=nil {

		log.Fatalf("error when dialing a network for %v: %v\n", "udp", err)
	} 
	defer conn.Close()
	
	m := "smap!helloworld"                                            
     	conn.Write([]byte(m+"\n"))
	needle := "udp"
	localAddr := strings.Split(conn.LocalAddr().String(), ":")
	localPort, _ := strconv.Atoi(localAddr[1])
	remoteIP := net.ParseIP(ip).To4()
	iph := make(chan *ipv4.Header, 2)
	// use an unused port and then receive a ICMP Port Unreachable message
	go func(){
		riph, _ := RscanRecvByRawConn(nil, remoteIP, localIP, 0, 0, 0, "icmp", "", needle, 0, []uint16{771, 0, 0}, timeout) 
		iph <- riph
		
	}()
	go func(){
		riph, _ := RscanRecvByRawConn(nil, remoteIP, localIP, port, uint16(localPort), 0, "udp", "", "", 0, nil, timeout) 
		iph <- riph
	}()
	riph1 := <- iph
	var riph *ipv4.Header
	if riph1 == nil {
		riph2 := <- iph
		if riph2 == nil {
			return -1
		} else {
			riph = riph2
		}
	} else {
		riph = riph1
	}
	
	return riph.ID
}

type packet struct {
	Settings       uint8  // leap yr indicator, ver number, and mode
	Stratum        uint8  // stratum of local clock
	Poll           int8   // poll exponent
	Precision      int8   // precision exponent
	RootDelay      uint32 // root delay
	RootDispersion uint32 // root dispersion
	ReferenceID    uint32 // reference id
	RefTimeSec     uint32 // reference timestamp sec
	RefTimeFrac    uint32 // reference timestamp fractional
	OrigTimeSec    uint32 // origin time secs
	OrigTimeFrac   uint32 // origin time fractional
	RxTimeSec      uint32 // receive time secs
	RxTimeFrac     uint32 // receive time frac
	TxTimeSec      uint32 // transmit time secs
	TxTimeFrac     uint32 // transmit time frac
}
	

func RscanGetIpidByUdp02(rawConn *ipv4.RawConn, ip, domain string, port uint16, timeout time.Duration) int {
	if rawConn == nil {
		c, rc := CreateRawConn("udp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	localIP := GetLocalIP()
	remoteIP := net.ParseIP(ip).To4()
	
	conn, err := net.Dial("udp", ip+":123")
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		log.Fatalf("failed to set deadline: %v", err)
	}
	udpConn, okk := conn.(*net.UDPConn)
	if !okk {
		log.Fatalf("failed to udpConnect: %v", okk)
	}
	addrs := strings.Split(udpConn.LocalAddr().String(), ":")
	if len(addrs) < 2 {
		log.Fatalf("failed to obtain local address")
	}
	localPort, err := strconv.Atoi(addrs[1])
	if err != nil {
		log.Fatalf("failed to retrieve local port")
	}
	req := &packet{Settings: 0x1B}

	// send time request
	if err := binary.Write(conn, binary.BigEndian, req); err != nil {
		log.Fatalf("failed to send request: %v", err)
	}
	riph, _ := RscanRecvByRawConn(rawConn, remoteIP, localIP, port, uint16(localPort), 0, "udp", "", "", 0, nil, timeout)
	if riph == nil { return -1 }

	return riph.ID
}


/////////////////////////////////////////////////////////My Func


// CreateRawFd creates packet socket via syscall.
func CreateRawFd() int {
    fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_IP))
    if err != nil {
		log.Fatalf("error when creating RawFd: %v\n", err)
	}
	//onesecond := syscall.NsecToTimeval(int64(time.Second))
	//syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &onesecond)
	return fd
}

// CreateRawConn creates net.PacketConn and ipv4.RawConn for TCP/UDP/ICMP.
func CreateRawConn(proto string) (net.PacketConn, *ipv4.RawConn) {
	c, err := net.ListenPacket("ip4:" + proto, "0.0.0.0") // To create a socket needs root previledge, so using sudo 
	if err!=nil {

		log.Fatalf("error when creating PacketConn for %v: %v\n", proto, err)
	}
	r, err := ipv4.NewRawConn(c)
	if err != nil {
		log.Fatalf("error when creating RawConn for %v: %v\n", proto, err)
	}
	return c, r
}

var id uint16
// SendTcpByRawConn sends TCP packet over ipv4.RawConn.
func SendTcpByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort uint16, flags string, seq, ack uint32, rn int, payload []byte) int {
	if rawConn == nil {
		c, rc := CreateRawConn("tcp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	
	tipl := &layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	
	wtcpl := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), 
		DstPort: layers.TCPPort(dstPort),
		Seq: seq,
		Ack: ack,
		Window: 512,
		Options: []layers.TCPOption{
			layers.TCPOption{
				OptionType: layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData: []byte{0x05, 0xb4}, // 0x05b4 = 1460
			},
		},
	}
	if strings.Contains(flags, "S") { wtcpl.SYN = true }
	if strings.Contains(flags, "A") { wtcpl.ACK = true }
	if strings.Contains(flags, "F") { wtcpl.FIN = true }
	if strings.Contains(flags, "R") { wtcpl.RST = true }
	if strings.Contains(flags, "P") { wtcpl.PSH = true }
	wtcpl.SetNetworkLayerForChecksum(tipl)

	sbuf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths:true, ComputeChecksums:true}
	gopacket.SerializeLayers(sbuf, sopts,
		wtcpl,
		gopacket.Payload(payload),
	)
	wb := sbuf.Bytes()
	
	if dstIP.String() == "199.244.49.62" {
		id = id + uint16(1) // + uint16(rand.Intn(10))
	} else {
		id = id + uint16(1)
	}
	
	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			int(id), // 0
		FragOff:	0,
		TTL:		64,
		Protocol:	int(layers.IPProtocolTCP),
		Checksum:	0,
		Src:		srcIP,
		Dst:		dstIP,
	}
	
	for i := 0; i < rn; i++ {
		   
		err := rawConn.WriteTo(wiph, wb, nil)
		if err != nil {
			log.Printf("error when writing RawConn in SendTcpByRawConn(%v:%v->%v:%v): %v\n", srcIP, srcPort, dstIP, dstPort, err)
			return -1
		}

	}
	
	return 0
}

var qt2n map[string]uint16 = map[string]uint16{
	"A":		1,
	"NS":		2,
    "CNAME":	5,
    "SOA":		6,
    "MX":		15,
    "TXT":		16,
	"AAAA":		28,
    "SRV":		33,
    "DS":		43,
    "DNSKEY":	48,
    "SPF":		99,
    "ANY":		255,
}

// 1st DNS Query, MTU=1500
//ok := SendUdpByRawConn(rc, localIP, extIP, localPort, port, txid, 65535, domain, "ANY", 1)
// SendUdpByRawConn sends UDP packet over ipv4.RawConn.
func SendUdpByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort, txid, bufsize uint16, domain, qtype string, rn int) int {
        
	if rawConn == nil {
		c, rc := CreateRawConn("udp")
                
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	wdnsl := &layers.DNS{
		ID: txid,
		QR: false,// query or response
		RD: true, // Recursion desired
		OpCode: layers.DNSOpCodeQuery,
	}

	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
		
	}
      
	wdnsl.Questions = append(wdnsl.Questions,
		layers.DNSQuestion{
			Name:  []byte(domain),
			Type:  layers.DNSType(qt2n[qtype]),
			Class: layers.DNSClassIN, // the class of query
		})
      
	wdnsl.Additionals = append(wdnsl.Additionals,
		layers.DNSResourceRecord{
			Name:  []byte(""),
			Type:  41,
			Class: layers.DNSClass(uint16(bufsize)),
			TTL: 0x00008000,
		})


	tipl := &layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	wudpl := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	wudpl.SetNetworkLayerForChecksum(tipl)

	sbuf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths:true, ComputeChecksums:true}
	gopacket.SerializeLayers(sbuf, sopts,
		wudpl,
		wdnsl,
	)
	wb := sbuf.Bytes()

	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			0,
		FragOff:	0,
		TTL:		64,
		Protocol:	int(layers.IPProtocolUDP),
		Checksum:	0,
		Src:		srcIP,
		Dst:		dstIP,
	}

	for i := 0; i < rn; i++ {
		err := rawConn.WriteTo(wiph, wb, nil)
		if err != nil {
			log.Printf("error when writing RawConn in SendUdpByRawConn(%v:%v->%v:%v): %v\n", srcIP, srcPort, dstIP, dstPort, err)
			return -1
		}
	}
	return 0
}
// ok := SendIcmpByRawConn(nil, srcIP, extIP, []uint16{3*256+4, uint16(seq), uint16(nhmtu)}, 1, payload1) // send a ICMP MTU message,RscanRecvByRawConn type=3, code=4, that means datagram is too big.
// SendIcmpByRawConn sends ICMP packet over ipv4.RawConn.
// icmp []uint16: TypeCode, Id, Seq.
// unreachable typ=3, code: net=0, host=1, PTB=4, SRF=5
// TLE typ=11, code: TTL=0
// echo type=8, code=0
// reply type=0, code=0
func SendIcmpByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, icmp []uint16, rn int, payload []byte) int {
	if rawConn == nil {
		c, rc := CreateRawConn("icmp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
       
	wicmpl := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeCode(icmp[0]),
		Id: icmp[1],
		Seq: icmp[2], // see the structure of different types of ICMP messages, for echo request and reply contains id and seq; but for ICMP MTU message here should be unused and net-hop MTU 
	}

	sbuf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{ComputeChecksums:true}
	gopacket.SerializeLayers(sbuf, sopts,
		wicmpl,
		gopacket.Payload(payload),
	)
	wb := sbuf.Bytes()
	var ttl int
	if srcIP.String() == "8.8.8.8" { 
		ttl = 40
	} else {
		ttl = 64
	}
	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			0,
		FragOff:	0,
		TTL:		ttl, 
		Protocol:	int(layers.IPProtocolICMPv4),
		Checksum:	0,
		Src:		srcIP,
		Dst:		dstIP,
	}

	for i := 0; i < rn; i++ {
		
		err := rawConn.WriteTo(wiph, wb, nil)
		if err != nil {
			log.Printf("error when writing RawConn in SendIcmpByRawConn(%v->%v): %v\n", srcIP, dstIP, err)
			return -1
		}
	
		
	}
	return 0
}

func PortListen(rawConn *ipv4.RawConn, dstIP net.IP, dstPort, ipid uint16, proto, flags string) {
	if rawConn == nil {
		c, rc := CreateRawConn(proto)
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	id = ipid
	rb := make([]byte, 1500) // the maximal capacity of ethenet link
	
	for {
                riph, _, _, err := rawConn.ReadFrom(rb)
		if err != nil {
			log.Printf("error when reading RawConn ReadDeadline\n")
			continue
		}
		
		if proto == "tcp" && riph.Protocol != int(layers.IPProtocolTCP) { continue }
		srcIP := riph.Src
		packet := gopacket.NewPacket(rb, layers.LayerTypeIPv4, gopacket.Default)
			
		if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		        
			rtcpl, ok := l.(*layers.TCP)
			
			if !ok {
				log.Printf("error when parsing TCP\n")
				continue
			}
			
			//if uint16(rtcpl.DstPort) == dstPort {
			match := false
			//if strings.Contains(flags, "SA") && rtcpl.SYN && rtcpl.ACK { match = true }
			if strings.Contains(flags, "SA") && !rtcpl.FIN && !rtcpl.RST && !rtcpl.PSH && rtcpl.ACK {match = true} // SA or A
			if match {
				srcPort := rtcpl.SrcPort
				dstPort := rtcpl.DstPort
				ack := rtcpl.Seq + 1
				SendTcpByRawConn(nil, dstIP, srcIP, uint16(dstPort), uint16(srcPort), "RA", 0, ack, 1, nil)
				//fmt.Println("send one!")
			}
			//}
		}

	}
}

func RscanRecvByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort, txid uint16, proto, flags, needle string, ack uint32, icmp []uint16, timeout time.Duration) (*ipv4.Header, gopacket.Packet) {
	if rawConn == nil {
		c, rc := CreateRawConn(proto)
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}
	
	rb := make([]byte, 1500) // the maximal capacity of ethenet link
	
	
	ddl := time.Now().Add(timeout)
	for {
		
		if time.Now().After(ddl) { break }
		if err := rawConn.SetReadDeadline(ddl); err != nil {
			
			log.Printf("error when setting RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v) with a needle (%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, needle, err)
			continue
		}
	        //func (c *RawConn) ReadFrom(b []byte) (h *Header, p []byte, cm *ControlMessage, err error)
	 	
                riph, _, _, err := rawConn.ReadFrom(rb)
		
		if err != nil {
			//log.Printf("error when reading RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
			continue
		}
		
		if !riph.Src.Equal(srcIP) { continue }  // Uncommented this to test against the networks behind a NAT or firewall (there exists address rewriting.)
		if !riph.Dst.Equal(dstIP) { continue } // due to the multiple ip addresses 
		if proto == "tcp" && riph.Protocol != int(layers.IPProtocolTCP) { continue }
		//if proto == "udp" && riph.Protocol != int(layers.IPProtocolUDP) { continue }
		if proto == "icmp" && riph.Protocol != int(layers.IPProtocolICMPv4) { continue }
		
		packet := gopacket.NewPacket(rb, layers.LayerTypeIPv4, gopacket.Default)
		
		if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
			
			ricmpl, ok := l.(*layers.ICMPv4)
		
			if !ok {
				log.Printf("error when parsing ICMP in RecvByRawConn(%v, %v->%v): %v\n", proto, srcIP, dstIP, err)
				continue
			}
			if strings.Contains(needle, "udp") && uint16(ricmpl.TypeCode) == 771 { // icmp port unreachable message
				//log.Printf("Received ICMP port unreachable message: %v:%v\n", packet, riph.ID)
				return riph, packet
			}
			if uint16(ricmpl.TypeCode) == 0 { // icmp reply
				
				if ricmpl.Id == icmp[1] && ricmpl.Seq == icmp[2] {
					return riph, packet
				}
			}
			continue
		}
		// riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil)
			
		if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		        
			rtcpl, ok := l.(*layers.TCP)
			
			if !ok {
				log.Printf("error when parsing TCP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, 	dstIP, dstPort, err)
				continue
			}
			if uint16(rtcpl.DstPort) == dstPort {
				match := false
				if ack != 0 && rtcpl.Ack != ack { match = false }
				//if strings.Contains(flags, "SA") && rtcpl.SYN && rtcpl.ACK { match = true } 
				if strings.Contains(flags, "SA") && !rtcpl.FIN && !rtcpl.RST && !rtcpl.PSH && rtcpl.ACK {match = true} // SA or A
				if strings.Contains(flags, "R") && rtcpl.RST { match = true }
				if match {
					
					return riph, packet
				}
				
			}
		}

		if l := packet.Layer(layers.LayerTypeUDP); l != nil {
			rudpl, ok := l.(*layers.UDP)
			if !ok {
				log.Printf("error when parsing UDP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
				continue
			}
			if uint16(rudpl.DstPort) == dstPort  && uint16(rudpl.SrcPort) == srcPort{
				//fmt.Printf("Received a DNS response: %v:%v\n", packet, riph.ID)
				return riph, packet
					
			}
		}
	}
	return nil, nil
}



// RecvByRawConn receives TCP/UDP/ICMP packet over ipv4.RawConn.
// icmp []uint16: TypeCode, Id, Seq.
func RecvByRawConn(rawConn *ipv4.RawConn, srcIP, dstIP net.IP, srcPort, dstPort, txid uint16, proto, flags, needle string, ack uint32, icmp []uint16) (*ipv4.Header, gopacket.Packet) {
	if rawConn == nil {
		c, rc := CreateRawConn(proto)
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	rb := make([]byte, 1500) // the maximal capacity of ethenet link
	timeout := 950 * time.Millisecond //2000
	ddl := time.Now().Add(timeout)

	for {
		if time.Now().After(ddl) { break }
		if err := rawConn.SetReadDeadline(ddl); err != nil {
			log.Printf("error when setting RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
			continue
		}
	//func (c *RawConn) ReadFrom(b []byte) (h *Header, p []byte, cm *ControlMessage, err error)
		riph, _, _, err := rawConn.ReadFrom(rb)
		
                
		
		if err != nil {
			//log.Printf("error when reading RawConn ReadDeadline in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
                        
			continue
		}

		if !riph.Src.Equal(srcIP) { continue }
		
		if proto == "tcp" && riph.Protocol != int(layers.IPProtocolTCP) { continue }
		if proto == "udp" && riph.Protocol != int(layers.IPProtocolUDP) { continue }
		if proto == "icmp" && riph.Protocol != int(layers.IPProtocolICMPv4) { continue }
		
		packet := gopacket.NewPacket(rb, layers.LayerTypeIPv4, gopacket.Default)
		//fmt.Print("received:", packet)

		if l := packet.Layer(layers.LayerTypeICMPv4); l != nil {
			
			ricmpl, ok := l.(*layers.ICMPv4)
		
			if !ok {
				log.Printf("error when parsing ICMP in RecvByRawConn(%v, %v->%v): %v\n", proto, srcIP, dstIP, err)
				continue
			}
			if uint16(ricmpl.TypeCode) == icmp[0] {
				if ricmpl.Id == icmp[1] && ricmpl.Seq == icmp[2] {
					return riph, packet
				}
			}
			continue
		}
		// riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil)
			
		if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		       

			rtcpl, ok := l.(*layers.TCP)
			
			if !ok {
				log.Printf("error when parsing TCP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
				continue
			}
			if uint16(rtcpl.DstPort) == dstPort {
				match := true
				if strings.Contains(flags, "S") && !rtcpl.SYN { match = false }
				if strings.Contains(flags, "A") && !rtcpl.ACK { match = false }    				
				if strings.Contains(flags, "F") && !rtcpl.FIN { match = false }
				if strings.Contains(flags, "R") && !rtcpl.RST { match = false }				
				if strings.Contains(flags, "P") && !rtcpl.PSH { match = false }
				
				if ack != 0 && rtcpl.Ack != ack { match = false }
				if srcPort == 443 {
					if strings.Contains(flags, "A") && (rtcpl.ACK) { match = true }
					if len(rtcpl.Payload) < 68  { match = false }
					
				        if needle != "" && !(needle == strconv.FormatUint(uint64(rtcpl.Seq), 10)) { match = false }
				} else {
				
					pl := strings.ToUpper(string(rtcpl.Payload))
					//fmt.Println("Payload:", pl)
					if needle != "" && !strings.Contains(pl, needle) { match = false }
				}
				
				//fmt.Println("match: %v", match)
				if match {
					return riph, packet
				}
				
			}
		}

		if l := packet.Layer(layers.LayerTypeUDP); l != nil {
			rudpl, ok := l.(*layers.UDP)
			if !ok {
				log.Printf("error when parsing UDP in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
				continue
			}
			if uint16(rudpl.DstPort) == dstPort {
				if l := packet.Layer(layers.LayerTypeDNS); l!=nil {
					rdnsl, ok := l.(*layers.DNS)
					if !ok {
						log.Printf("error when parsing DNS in RecvByRawConn(%v, %v:%v->%v:%v): %v\n", proto, srcIP, srcPort, dstIP, dstPort, err)
						continue
					}
					
					if rdnsl.ID == txid && rdnsl.QR {
						return riph, packet
					}
				}
			}
		}
	}
	return nil, nil
}




// GetIpidByTcp gets IPID by TCP SYN/ACK.
func GetIpidByTcp(rawConn *ipv4.RawConn, ip string, port uint16) int {
	if rawConn == nil {
		c, rc := CreateRawConn("tcp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535

	ok := SendTcpByRawConn(rawConn, localIP, extIP, localPort, port, "S", 0, 0, 1, nil)
	if ok == -1 { 
             return -1 
	}

	riph, rpkt := RecvByRawConn(rawConn, extIP, localIP, port, localPort, 0, "tcp", "SA", "", 0, nil)
	if riph == nil { 
	     return -1 
	}
	//My test
	rtcpl, _ := rpkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	
	ack := rtcpl.Seq + 1
	ok = SendTcpByRawConn(rawConn, localIP, extIP, localPort, port, "A", 1, ack, 1, nil)
	if ok == -1 { 
              return -1 
	 }
	return riph.ID
}

// GetIpidByUdp gets IPID by UDP DNS.
func GetIpidByUdp(rawConn *ipv4.RawConn, ip, domain string, port uint16) int {
	if rawConn == nil {
		c, rc := CreateRawConn("udp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	txid := uint16(rand.Int()) & 0xffff

	ok := SendUdpByRawConn(rawConn, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
	if ok == -1 { return -1 }

	riph, _ := RecvByRawConn(rawConn, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil)
	if riph == nil { return -1 }

	return riph.ID
}

//For my test
func MyServantGetIpidByIcmp(rawConn *ipv4.RawConn, ip string, id uint16, seq uint16) int {
	if rawConn == nil {
		c, rc := CreateRawConn("icmp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

        srcIP := net.ParseIP("199.244.49.220").To4() // spoofing the source IP address
	dstIP := net.ParseIP(ip).To4()
	
	// ICMP TypeCode = (8, 0) = 8 * 256 + 0 = Echo
	ok := SendIcmpByRawConn(rawConn, srcIP, dstIP, []uint16{8*256, id, seq}, 1, nil) // ICMP data is nil (64bits)
	if ok == -1 { return -1}
	return 0
}


// GetIpidByIcmp gets IPID by ICMP Ping.
func GetIpidByIcmp(rawConn *ipv4.RawConn, ip string) int {
	if rawConn == nil {
		c, rc := CreateRawConn("icmp")
		defer c.Close()
		defer rc.Close()
		rawConn = rc
	}

	localIP := GetLocalIP()
        //localIP := net.ParseIP("199.244.49.220").To4()
	extIP := net.ParseIP(ip).To4()
	id := uint16(rand.Int()) & 0xffff
	seq := uint16(rand.Int()) & 0xffff

	// ICMP TypeCode = (8, 0) = 8 * 256 + 0 = Echo
	ok := SendIcmpByRawConn(rawConn, localIP, extIP, []uint16{8*256, id, seq}, 1, nil)
	if ok == -1 { return -1 }

	// ICMP TypeCode = (0, 0) = 0 * 256 + 0 = Echo Reply
	riph, _ := RecvByRawConn(rawConn, extIP, localIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq})
	if riph == nil { return -1 }

	return riph.ID
}
func RscanWriteToServant(sip, sport, cmd string) int {
	servantConn, err := net.Dial("tcp4", sip+":"+sport)
	defer servantConn.Close()
	if err!=nil {
		log.Printf("error when establishing a connection with servant: %v\n", err)
		return -1
	}
	_, err = servantConn.Write([]byte(cmd))
        if err!=nil {
		log.Printf("error when writing TCP to Servant: %v\n", err)
		return -1
        }
	return 0
}


//My test using R scan, the same with the previous function will be removed after testing 
func RscanGetIpidByServant(conn net.Conn, cmd string) int {
	_, err := conn.Write([]byte(cmd))
        if err!=nil {
		log.Printf("error when writing TCP to Servant: %v\n", err)
		return -1
        }

	if cmd=="0,0" { return 0 }

	buf := make([]byte, 1500)
	bufLen, err := conn.Read(buf)
	if err!=nil {
		log.Printf("error when reading TCP from Servant: %v\n", err)
		return -1
	}

	id, err := strconv.Atoi(string(buf[:bufLen]))
	
	if err!=nil {
		log.Printf("error when converting string from Servant: %v\n", err)
		return -1
	}

	return id
}

// For my test
func MyGetIpidByServant(rawConn *ipv4.RawConn, conn net.Conn, cmd string, ip string) int {
	_, err := conn.Write([]byte(cmd))
    if err!=nil {
		log.Printf("error when writing TCP to Servant: %v\n", err)
		return -1
    }

	if cmd=="0,0" { return 0 }

	buf := make([]byte, 1500)
	
	bufLen, err := conn.Read(buf)
	if err!=nil {
		log.Printf("error when reading TCP from Servant: %v\n", err)
		return -1
	}

	res := string(buf[:bufLen])
	fmt.Println("Servant res:", res)
	fields := strings.Split(res, ",")
	if len(fields) < 2 { return -1 }

	id0, err0:= strconv.Atoi(fields[0])
	seq0, err1 := strconv.Atoi(fields[1])
	
	if err0!=nil || err1 !=nil {
		log.Printf("error when converting string from Servant: %v\n", err)
		return -1
	}
	
	id := uint16(id0)
	seq := uint16(seq0)
	srcIP := GetLocalIP()
	dstIP := net.ParseIP(ip).To4()
	riph, _ := RecvByRawConn(rawConn, dstIP, srcIP, 0, 0, 0, "icmp", "", "", 0, []uint16{0, id, seq})
	
	if riph == nil { return -1 }
	fmt.Println("MyServant riph: ", riph.String())
	return riph.ID
	
}




// GetIpidByServant triggers Servant to get IPID.
// cmd:
//   0,0 stop
//   ip,proto proto: [icmp, udp, tcp80, tcp25, tcp53] tcp23
func GetIpidByServant(conn net.Conn, cmd string) int {
	_, err := conn.Write([]byte(cmd))
    if err!=nil {
		log.Printf("error when writing TCP to Servant: %v\n", err)
		return -1
    }

	if cmd=="0,0" { return 0 }

	buf := make([]byte, 1500)
	bufLen, err := conn.Read(buf)
	if err!=nil {
		log.Printf("error when reading TCP from Servant: %v\n", err)
		return -1
	}

	id, err := strconv.Atoi(string(buf[:bufLen]))
	
	if err!=nil {
		log.Printf("error when converting string from Servant: %v\n", err)
		return -1
	}

	return id
}

// IpidErr checks if IPIDs contains -1.
func IpidErr(ids []int) bool {
	for _, id := range ids {
		if id==-1 {
			return true
		}
	}
	return false
}

// IpidZero checks if IPID is 0.
func IpidZero(ids []int) bool {
	zero := false
	// How about ipid=-1?
	for _, id := range ids {
		if id==0 {
			zero = true
		}
		if id!=0 && id!=-1 {
			zero = false
		}
	}
	return zero
}

func diff(a, b int) int {
	return (b + 65536 - a)%65536
}

// IpidSequential checks if IPIDs are sequential.
func IpidSequential(ids []int) bool {
	
	for i:=0; i<3; i++ {
	
		if diff(ids[i], ids[i+1])==0 || diff(ids[i], ids[i+1])>1000 {
			return false
		}
	}
	return true
}

func IpidSequentialAndIdle(ids []int, times []time.Time, v_thres int) (bool, int) {
	v := -9999
	spd := float64(0)
	for i:=0; i<len(ids)-1; i++ {
		gap := float64(diff(ids[i], ids[i+1]))
		dur := float64(times[i+1].Sub(times[i]).Nanoseconds())/1000000000.0 //unit: ID/s
		spd += gap/dur
	}
	spd /= float64(len(ids)-1)
	v = int(spd)
	log.Printf("The velocity observed of %v:%v\n", ids, v)
	if v > 800 { // remove random IPID 
		return false, v
	} 
	if v > v_thres { // remove constant IPID as well as a high velocity (busy)
		return false, v
	}
	return true, v
}

// IpidSpoofable checks if IPID is spoofed.
func IpidSpoofable(ids []int, times []time.Time) bool {
	spd := float64(0)
	for i:=0; i<3; i++ {
		gap := float64(diff(ids[i], ids[i+1]))
		dur := float64(times[i+1].Sub(times[i]).Nanoseconds())/1000000.0
		spd += gap/dur
	}
	spd /= 3.0
	delta := diff(ids[3], ids[4])
	dur2 := float64(times[4].Sub(times[3]).Nanoseconds())/1000000.0
	threshold := spd*dur2+8.0

	if delta>=8 && delta<=1000 && float64(delta)>= threshold{
		log.Println("identified spoofable ip:", delta, threshold, ids)
		return true

	} else {
		log.Println("Not found ip:", delta, threshold, ids)
		return false
	}
}

// For my test
func MyIpidSpoofable(ip string, ids []int, times []time.Time, probes, v int) bool {
	spd := float64(v) // unit: ID/s
	delta := diff(ids[len(ids)-2], ids[len(ids)-1])
	dur2 := float64(times[len(ids)-1].Sub(times[len(ids)-2]).Nanoseconds())/1000000000.0
	log.Printf("Time duration: %v\n", dur2)
        threshold := int(math.Ceil(spd*dur2+0.8*float64(probes))) // set 0.2*probes as the fault margin. 
	if delta<=1000 && delta>=threshold {
		log.Println("identified spoofable ip:", delta, threshold, ip, ids, v)
		return true
	} else {
		log.Println("Not found ip:", delta, threshold, ip, ids, v)
		return false
	}
}
// IpidTestIcmp tests if IP is spoofable via ICMP.
func IpidTestIcmp(ip, sip, sport string) (int, []int) {
	conn, err := net.Dial("tcp4", sip+":"+sport)
	if err!=nil {
		log.Printf("error when dialing TCP in IpidTestICMP(%v): %v\n", ip, err)
		return -4, []int{}
	}
	defer conn.Close()
	defer GetIpidByServant(conn, "0,0")

	c, rc := CreateRawConn("icmp")
	defer c.Close()
	defer rc.Close()

	ids := make([]int, 5, 5)
	times := make([]time.Time, 5, 5)
	ids[0] = GetIpidByIcmp(rc, ip)
	times[0] = time.Now()
	ids[1] = GetIpidByServant(conn, ip+",icmp")
	times[1] = time.Now()
	ids[2] = GetIpidByIcmp(rc, ip)
	times[2] = time.Now()
	ids[3] = GetIpidByServant(conn, ip+",icmp")
	times[3] = time.Now() // The time not consider the delay generated by the communication beween these two testers!!!
	//fmt.Println("ids:", ip, ids)
	if IpidErr(ids) { return -3, ids }
	if IpidZero(ids[:4]) { return -2, ids }
	if !IpidSequential(ids) { return -1, ids }
	
	//localIP := GetLocalIP()
	neibIP := GetNeighbour(ip)
	extIP := net.ParseIP(ip).To4()
	
	probes := 10
	for i := 0; i<probes; i++ {
		id := uint16(rand.Int()) & 0xffff
		SendIcmpByRawConn(nil, neibIP, extIP, []uint16{8*256, id, 0}, 1, nil) // id = 0
	}
	
	ids[4] = GetIpidByIcmp(rc, ip)
	times[4] = time.Now()
	
	if IpidErr(ids) { return -3, ids }
	if IpidSpoofable(ids, times) { 
		return 1, ids
	} else {
		return 0, ids
	}
}





 // For my test
func MyIpidTestIcmp02(ip, sip, sport string) (int, []int) {
	conn, err := net.Dial("tcp4", sip+":"+sport)
	if err!=nil {
		log.Printf("error when dialing TCP in IpidTestICMP(%v): %v\n", ip, err)
		return -4, []int{}
	}
	defer conn.Close()
	defer GetIpidByServant(conn, "0,0")

	c, rc := CreateRawConn("icmp")
	defer c.Close()
	defer rc.Close()
	probes := 4
	ids := make([]int, probes+1, probes+1)
	times := make([]time.Time, probes+1, probes+1)
	
	for i:=0; i<probes; {
        	ids[i] = GetIpidByIcmp(rc, ip)
		times[i] = time.Now()
		ids[i+1] = GetIpidByServant(conn, ip+",icmp")
		times[i+1] = time.Now()
		i = i+2
	}

	if IpidErr(ids[:probes]) { 
		log.Println(ip, ids)
		return -3, ids 
	}
	if IpidZero(ids[:probes]) { 
		log.Println(ip, ids)
		return -2, ids 
	}
	if !IpidSequential(ids[:probes]) { 
		log.Println(ip, ids)
		return -1, ids 
	}
	
	localIP := GetLocalIP()
	//neibIP := GetNeighbour(ip)
	extIP := net.ParseIP(ip).To4()
	SendIcmpByRawConn(nil, localIP, extIP, []uint16{8*256, 8888, 0}, 50, nil) // Sending 20 spoofed packets, considering not consecutive???
	ids[probes] = GetIpidByIcmp(rc, ip)
	times[probes] = time.Now()

       
	
	if IpidErr(ids) { return -3, ids }
	if MyIpidSpoofable(ip, ids, times, probes, 0) {
		return 1, ids
	} else {
		return 0, ids
	}
}

// IpidTestUdp tests if IP is spoofable via UDP DNS.
func IpidTestUdp(ip, domain, sip, sport string, port uint16) (int, []int) {
	conn, err := net.Dial("tcp4", sip+":"+sport)
	if err!=nil {
		log.Printf("error when dialing TCP in IpidTestUdp(%v): %v\n", ip, err)
		return -4, []int{}
	}
	defer conn.Close()
	defer GetIpidByServant(conn, "0,0")

	c, rc := CreateRawConn("udp")
	defer c.Close()
	defer rc.Close()

	ids := make([]int, 5, 5)
	times := make([]time.Time, 5, 5)
	ids[0] = GetIpidByUdp(rc, ip, domain, port)
	times[0] = time.Now()
	ids[1] = GetIpidByServant(conn, ip+",udp,"+domain)
	times[1] = time.Now()
	ids[2] = GetIpidByUdp(rc, ip, domain, port)
	times[2] = time.Now()
	ids[3] = GetIpidByServant(conn, ip+",udp,"+domain)
	times[3] = time.Now()
	if IpidErr(ids) { return -3, ids }
	if IpidZero(ids[:4]) { return -2, ids }
	if !IpidSequential(ids) { return -1, ids }
	
	//neibIP := GetNeighbour(ip)
	neibIP := GetSpoofedIP(ip, domain)
	extIP := net.ParseIP(ip).To4()
	SendUdpByRawConn(nil, neibIP, extIP, 8888, port, 8888, 65535, domain, "A", 10)
	ids[4] = GetIpidByUdp(rc, ip, domain, port)
	times[4] = time.Now()
	log.Println(ip, ids, neibIP.String())
	if IpidErr(ids) { return -3, ids }
	if IpidSpoofable(ids, times) {
		return 1, ids
	} else {
		return 0, ids
	}
}

// IpidTestTcp tests if IP is spoofable via TCP SYN/ACK.
func IpidTestTcp(ip, domain, sip, sport string, port uint16) (int, []int) {
	conn, err := net.Dial("tcp4", sip+":"+sport)
	if err!=nil {
		log.Printf("error when dialing TCP in IpidTestTcp(%v, %v): %v\n", ip, port, err)
		return -4, []int{}
	}
	defer conn.Close()
	defer GetIpidByServant(conn, "0,0")
	
	c, rc := CreateRawConn("tcp")
	defer c.Close()
	defer rc.Close()

	ids := make([]int, 5, 5)
	times := make([]time.Time, 5, 5)
	
	ids[0] = GetIpidByTcp(rc, ip, port) // my test: nil
	times[0] = time.Now()
	
	
	ids[1] = GetIpidByServant(conn, ip+",tcp"+strconv.Itoa(int(port)))
	times[1] = time.Now()
	
	ids[2] = GetIpidByTcp(rc, ip, port)
	times[2] = time.Now()
	
	
	ids[3] = GetIpidByServant(conn, ip+",tcp"+strconv.Itoa(int(port)))
	times[3] = time.Now()
	//fmt.Println("ids01:", ip, ids)
	if IpidErr(ids) { return -3, ids }
	if IpidZero(ids[:4]) { return -2, ids }
	if !IpidSequential(ids) { return -1, ids }
	//localIP := GetLocalIP()
	//neibIP := GetNeighbour(ip)
	neibIP := GetSpoofedIP(ip, domain)
	extIP := net.ParseIP(ip).To4()
	var wg sync.WaitGroup
	probes := 10
	for i := 0; i<probes; i++ {
		localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
		wg.Add(1)
		go func(localPort uint16) {
			defer wg.Done()
			SendTcpByRawConn(rc, neibIP, extIP, localPort, port, "S", 0, 0, 1, nil)
		}(localPort)		
	} 

	wg.Wait()
	
	//MyRecvByRawConn(rc, extIP, localIP, port, 8888, 0, "tcp", "T", "", 0, nil)
	
	//time.Sleep(elapsed/2*time.Duration(probes))
	ids[4] = GetIpidByTcp(rc, ip, port)
	times[4] = time.Now()
	//fmt.Println("ids02:", ip, ids)
	if IpidErr(ids) { return -3, ids }
	if IpidSpoofable(ids, times) {
		return 1, ids
	} else {
		return 0, ids
	}
}

func MyPmtudTest(proto, ip, domain, sip, sport string, port uint16) []int {
	

	var res1 []int

	
	if proto == "tcp" {
		res1 = MyGetPmtudByTcp(ip, domain, port, false) //Start testing... (02.04, 18:00)
		
	}
	if proto == "udp" {
		res1 = GetPmtudByUdp(ip, domain, port, false) // No spoofing
		fmt.Println("Only Local server UDP: ", res1)
	}
	

	
	return res1
}



// PmtudTest tests if IP is spoofable via PMTUD for TCP.
// return value:
//    []: res, rlen1, rmf1*10+rdf1, nhmtu, rlen2, rmf2*10+rdf2, rlen3, rmf3*10+rdf3
//   -30: disconnect from Servant
//   -23: error when contacting Servant
//   -22: error when sending cmd
//   -21: error when receiving res
//   -18: error when sending TCP SYN
//   -17: error when receiving TCP SYN/ACK
//   -16: error when sending TCP ACK  -- retrieving local port from TCPConn
//   -15: error when sending 1st request
//   -14: error when receiving 1st response
//   -13: error when sending ICMP PTB
//   -12: error when sending 2nd request
//   -11: error when receiving 2nd response
//	  -2: DF not set and not fragmented
//    -1: DF set but no action or DF not set but doesn't reduce size
//     0: PMTUD enabled
//     1: spoofable
func PmtudTest(proto, ip, domain, sip, sport string, port uint16) []int {
	conn, err := net.Dial("tcp4", sip+":"+sport)
	if err!=nil {
		log.Printf("error when dialing TCP in PmtudTest(%v, %v, %v): %v\n", proto, ip, port, err)
		return []int{-23, 0, 0, 0, 0, 0, 0, 0}
	}
	defer conn.Close()
	defer GetPmtudByServant(conn, "0,0,0")

	//var res1, res2, res []int
	var res1, res2, res []int
	
	
	masterDone := make(chan bool)
	servantDone := make(chan bool)
	go func() {
		if proto == "tcp" {

			//res1 = GetPmtudByTcp(ip, domain, port, false) // No spoofing
			res1 = MyGetPmtudByTcp(ip, domain, port, false) // No spoofing
			
		}
		if proto == "udp" {
			res1 = GetPmtudByUdp(ip, domain, port, false) 
			
		}
		masterDone <- true
	}()
	go func() {
		if proto == "tcp" {
			res2 = GetPmtudByServant(conn, ip+",tcp"+strconv.Itoa(int(port))+","+domain) // set as spoofed
			
			
		}
		if proto == "udp" {
			res2 = GetPmtudByServant(conn, ip+",udp,"+domain)
			

		}
		servantDone <- true
	}()
	<-masterDone
	<-servantDone

	if res2[0] >= res1[0] {
		res =  []int{res2[0], res2[1], res2[2], res2[3], res1[4], res1[5], res2[4], res2[5]}
	} else {
		res = append(res1, res2[4], res2[5])
	}
	if res2[0] == 0 { res[0] = 1 }
	return res
}

// Str2Ints convert "int,int..." to []int
func Str2Ints(s string) []int {
	ints := strings.Split(s, ",")
	res := make([]int, 0, 10)
	for _, is := range(ints) {
		i := -99
		i, _ = strconv.Atoi(is)
		res = append(res, i)
	}
	return res
}

// Ints2Str convert []int to "int,int..."
func Ints2Str(n []int) string {
	ints := make([]string, 0, 10)
	for _, i := range(n) {
		ints = append(ints, strconv.Itoa(i))
	}
	return strings.Join(ints, ",")
}

// GetPmtudByServant triggers Servant to check spoof PMTUD.
// cmd:
//   0,0,0 stop
//   ip,proto,domain proto: [udp, tcp80, tcp25, tcp53]
func GetPmtudByServant(conn net.Conn, cmd string) []int {
	_, err := conn.Write([]byte(cmd))
    if err!=nil {
		log.Printf("error when writing TCP to Servant: %v\n", err)
		return []int{-22, 0, 0, 0, 0, 0}
    }

	if cmd=="0,0,0" {
		return []int{-30, 0, 0, 0, 0, 0}
	}

	buf := make([]byte, 1500)
	bufLen, err := conn.Read(buf)
	if err!=nil {
		log.Printf("error when reading TCP from Servant: %v\n", err)
		return []int{-21, 0, 0, 0, 0, 0}
	}

	return Str2Ints(string(buf[:bufLen]))
}



func MyGetPmtudByTcp(ip, domain string, port uint16, spoof bool) []int {
	
	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	seq := uint32(rand.Int()) & 0xffffffff
	mtus := make([]int, 6, 6)

	cert, err := tls.LoadX509KeyPair("certs/MyClient.pem", "certs/MyClient.key")
	if err != nil {
	   log.Println("server: loadkeys: %s", err)
	 }
	 config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	 config.ServerName = domain
	 tlsConn, err := tls.Dial("tcp", ip+":443", &config)
	 if err != nil {
		mtus[0] = -17
		return mtus
	 }
	addrs := strings.Split(tlsConn.LocalAddr().String(), ":")
	if len(addrs) < 2 {
		mtus[0] = -16
		return mtus
	}
	localPort, err := strconv.Atoi(addrs[1])
	if err != nil {
		mtus[0] = -16
		return mtus
	}

	// Query
	needle := "220"
	//rb := make([]byte, 1500)
	if port == 443 {
                
		 log.Println("client: connected to: ", tlsConn.RemoteAddr())
		// make a client Hello
		//_, _, err = tlsConn.makeClientHello()

		//if err != nil {

		//    fmt.Println("handshake hello:", err)
		//}

		
	    // 1st HTTP request
	    httpHEAD := []byte("HEAD / HTTP/1.1\r\nHost: www."+domain+"\r\nConnection: close\r\n\r\n")
	    ddl := time.Now().Add(TIMEOUT)
	    tlsConn.SetWriteDeadline(ddl)
	    //_, err = io.WriteString(tlsConn, string(httpGet))
	 
	    _, err = tlsConn.Write(httpHEAD) // How to check write have been done?
	    if err != nil {
	     	mtus[0] = -15
	    	return mtus
	     }
	 
	 needle = "" 
	
	}
	
	c, rc := CreateRawConn("tcp") // Before, it was placed on the top of this function, that means, the connection was opened early, so 						we can alwaysa receive all of the reponses from the server. 
	defer c.Close()
	defer rc.Close()
	defer tlsConn.Close()
	riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "PA", needle, 0, nil)
	if riph1 == nil {
		mtus[0] = -14
		return  mtus
	}
	ripl1, _ := rpkt1.Layer(layers.LayerTypeIPv4).(*layers.IPv4) 
	rlen1 := ripl1.Length
	rtcpl1, _ := rpkt1.Layer(layers.LayerTypeTCP).(*layers.TCP)
	
	needle = strconv.FormatUint(uint64(rtcpl1.Seq), 10)
	//fmt.Println("needle:", needle)
	mtus[1] = int(rlen1)
	rdf1 := 0
	if (ripl1.Flags & layers.IPv4DontFragment) == layers.IPv4DontFragment { rdf1 = 1 }   //DF = 1
	mtus[2] = rdf1
	if rdf1 == 0 {
		mtus[0] = -2 // -2: DF not set and not fragmented
		return mtus
	}
	
	payload1 := append(ripl1.Contents, ripl1.Payload[:8]...) //IP header + the first 8 bytes of the original dataprogram's data, why ...
	
        // ICMP PTB
	nhmtu := 68
	mtus[3] = int(nhmtu)
	srcIP := localIP
	if spoof { 
		srcIP = GetNeighbour(ip) 
		log.Println(ip, "Using spoofing IP: ", srcIP)
	}

	ok := SendIcmpByRawConn(nil, srcIP, extIP, []uint16{3*256+4, uint16(seq), uint16(nhmtu)}, 1, payload1) // send a ICMP MTU message, type=3, 														//code=4, that means datagram is too big.
	if ok == -1 {
		mtus[0] = -13
		return mtus
	}
       
	// 2nd HTTP RESPONSE / SMTP MESSAGE
	riph2, rpkt2 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil) //needle is the seq number of the previous packet captured 
	if riph2 == nil {
		mtus[0] = -11
		return  mtus
	}
	ripl2, _ := rpkt2.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
    
	rlen2 := ripl2.Length
	mtus[4] = int(rlen2)
	rdf2 := 0
	if ripl2.Flags & layers.IPv4DontFragment == layers.IPv4DontFragment { rdf2 = 1 } // layers.IPv4DontFragment = DF
	mtus[5] = rdf2
	if !(rdf2 == 0 || rlen2 < rlen1) {
		mtus[0] = -1
		return mtus
	}
		
	
	mtus[0] = 0
	return mtus
}

// GetPmtudByTcp tests if IP of domain supports PMTUD via ICMP PTB for TCP.
// return value:
//    []: res, rlen1, rdf1, nhmtu, rlen2, rdf2
func GetPmtudByTcp(ip, domain string, port uint16, spoof bool) []int {
	c, rc := CreateRawConn("tcp")
	defer c.Close()
	defer rc.Close()

	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	seq := uint32(rand.Int()) & 0xffffffff
	mtus := make([]int, 6, 6)

	// TCP connect
	conn, err := net.DialTimeout("tcp4", extIP.String() + ":" + strconv.Itoa(int(port)), TIMEOUT)
	if err != nil {
		mtus[0] = -17
		return mtus
	}

	// TCP retrieve local port
	tcpConn, okk := conn.(*net.TCPConn)
	if !okk {
		mtus[0] = -16
		return mtus
	}
	addrs := strings.Split(tcpConn.LocalAddr().String(), ":")
	if len(addrs) < 2 {
		mtus[0] = -16
		return mtus
	}
	localPort, err := strconv.Atoi(addrs[1])
	if err != nil {
		mtus[0] = -16
		return mtus
	}

	// Query
	needle := "220"
	if port == 80 {
		// 1st HTTP REQUEST
		httpGet := []byte("GET / HTTP/1.1\r\nHost: www."+domain+"\r\nConnection: close\r\n\r\n") 
		ddl := time.Now().Add(TIMEOUT)
		tcpConn.SetWriteDeadline(ddl)
		_, err = tcpConn.Write(httpGet)
		if err != nil {
			mtus[0] = -15
			return mtus
		}
		
		needle = "HTTP"
		 
	}
	tcpConn.Close() // I tried to use CloseWrite() but it did not work.
	
	// 1st HTTP RESPONSE / SMTP MESSAGE
	riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil) // Why here needle must be "HTTP"
	if riph1 == nil {
		mtus[0] = -14
		return mtus
	}
	ripl1, _ := rpkt1.Layer(layers.LayerTypeIPv4).(*layers.IPv4) // retrieve IP data
        
	rlen1 := ripl1.Length
	mtus[1] = int(rlen1)
	rdf1 := 0
	if (ripl1.Flags & layers.IPv4DontFragment) == layers.IPv4DontFragment { rdf1 = 1 }   //DF = 1
	mtus[2] = rdf1
	if rdf1 == 0 {
		mtus[0] = -2 // -2: DF not set and not fragmented
		return mtus
	}
	
	payload1 := append(ripl1.Contents, ripl1.Payload[:8]...) //IP header + the first 8 bytes of the original dataprogram's data, why ...
	
        // ICMP PTB
	nhmtu := 68
	mtus[3] = int(nhmtu)
	srcIP := localIP
	if spoof { 
		//srcIP = GetNeighbour(ip) 
		srcIP = GetSpoofedIP(ip, domain) 
		log.Println(ip, "Using spoofing IP: ", srcIP)
	}
	
	ok := SendIcmpByRawConn(nil, srcIP, extIP, []uint16{3*256+4, uint16(seq), uint16(nhmtu)}, 1, payload1) // send a ICMP MTU message, type=3, code=4, that means datagram is too big.
	if ok == -1 {
		mtus[0] = -13
		return mtus
	}
       
	// 2nd HTTP RESPONSE / SMTP MESSAGE
	riph2, rpkt2 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), 0, "tcp", "", needle, 0, nil)
	if riph2 == nil {
		mtus[0] = -11
		return  mtus
	}
	ripl2, _ := rpkt2.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
    
	rlen2 := ripl2.Length
	mtus[4] = int(rlen2)
	rdf2 := 0
	if ripl2.Flags & layers.IPv4DontFragment == layers.IPv4DontFragment { rdf2 = 1 } // layers.IPv4DontFragment = DF
	mtus[5] = rdf2
	if !(rdf2 == 0 || rlen2 < rlen1) {
		mtus[0] = -1
		return mtus
	}
	mtus[0] = 0
	return mtus
}

// RecvByRawFd receives DNS response by syscall paket socket.
func RecvByRawFd(rawFd int, ip string, port, txid uint16) (int, int, int, int, int, []byte) {
	if rawFd == -1 {
		rawFd = CreateRawFd()
		defer syscall.Close(rawFd)
	}
	rb := make([]byte, 1500)
	ddl := time.Now().Add(TIMEOUT)
	for {
		if time.Now().After(ddl) {
			log.Printf("timeout when reading socket from %v\n", ip)
			break
		}

		n, _, err := syscall.Recvfrom(rawFd, rb, 0)
		if err!=nil {
			log.Printf("error when reading socket from %v: %v\n", ip, err)
		}

		srcIP := net.IPv4(rb[26], rb[27], rb[28], rb[29]).To4().String()
		if srcIP!=ip { continue }

		packet := gopacket.NewPacket(rb[:n], layers.LayerTypeEthernet, gopacket.Default)
		//fmt.Println("received packet:", packet.String())
		if il := packet.Layer(layers.LayerTypeIPv4); il!=nil {
			ripl, ok := il.(*layers.IPv4)
			if !ok {
				log.Printf("error when parsing IPv4 from %v: %v\n", ip, err)
				continue
			}
			if ripl.FragOffset>0 { continue }
			rDF := 0
			if ripl.Flags & layers.IPv4DontFragment == layers.IPv4DontFragment { rDF = 1 }
			rMF := 0
			if ripl.Flags & layers.IPv4MoreFragments == layers.IPv4MoreFragments { rMF = 1 }

			if ripl.Protocol == layers.IPProtocolUDP {
				rDstPort := binary.BigEndian.Uint16(ripl.Payload[2:4])
				if rDstPort != port { continue }
				rUDPLen := binary.BigEndian.Uint16(ripl.Payload[4:6])

				rTXID := binary.BigEndian.Uint16(ripl.Payload[8:10])
                                
				rQR := (0x80 & ripl.Payload[10] == 0x80)
				rTC := (0x02 & ripl.Payload[10]) >> 1
				if rTXID==txid && rQR {
					return rDF, rMF, int(ripl.Length), int(rUDPLen), int(rTC), append(ripl.Contents, ripl.Payload[:8]...)
				}
			}
		}
	}
	return -1, -1, -1, -1, -1, nil
}

func MyGetPmtudByUdp(ip, domain string, port uint16, spoof bool) []int {
	c, rc := CreateRawConn("udp")
	defer c.Close()
	defer rc.Close()
	
	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	txid := uint16(rand.Int()) & 0xffff
	mtus := make([]int, 6, 6)

	// 1st DNS Query, MTU=1500
	ok := SendUdpByRawConn(rc, localIP, extIP, localPort, port, txid, 65535, domain, "ANY", 1)
	if ok == -1 {
		mtus[0] = -15
		return mtus
	}
	// 1st DNS Reply
	riph1, rpkt1 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), txid, "udp", "", "", 0, nil)
	
	if riph1 == nil {
		mtus[0] = -14
		return mtus
	}
	ripl1, _ := rpkt1.Layer(layers.LayerTypeIPv4).(*layers.IPv4) // retrieve IP data

	rlen1 := ripl1.Length
	mtus[1] = int(rlen1)
	rdf1 := 0
	if (ripl1.Flags & layers.IPv4DontFragment) == layers.IPv4DontFragment { rdf1 = 1 }   //DF = 1
	mtus[2] = rdf1
	if rdf1 == 0 {
		mtus[0] = -2 // -2: DF not set and not fragmented
		return mtus
	}
	
	payload1 := append(ripl1.Contents, ripl1.Payload[:8]...) 
	
	// ICMP PTB
	nhmtu := 68
	mtus[3] = nhmtu
	srcIP := localIP
	if spoof { srcIP = GetNeighbour(ip) }
	ok = SendIcmpByRawConn(nil, srcIP, extIP, []uint16{3*256+4, txid, uint16(nhmtu)}, 1, payload1)
	if ok == -1 {
		mtus[0] = -13
		return mtus
	}
	// 2nd DNS Query, MTU=68
	ok = SendUdpByRawConn(rc, localIP, extIP, localPort, port, txid, 65535, domain, "ANY", 1)
	if ok == -1 {
		mtus[0] = -12
		return mtus
	}
	// 2nd DNS Reply
	riph2, rpkt2 := RecvByRawConn(rc, extIP, localIP, port, uint16(localPort), txid, "udp", "", "", 0, nil)
	if riph2 == nil {
		mtus[0] = -11
		return  mtus
	}
	ripl2, _ := rpkt2.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
    
	rlen2 := ripl2.Length
	mtus[4] = int(rlen2)
	rdf2 := 0
	if ripl2.Flags & layers.IPv4DontFragment == layers.IPv4DontFragment { rdf2 = 1 } // layers.IPv4DontFragment = DF
	mtus[5] = rdf2
	if !(rdf2 == 0 || rlen2 < rlen1) {
		mtus[0] = -1
		return mtus
	}
	mtus[0] = 0
	return mtus
}



// GetPmtudByUdp tests if IP of domain supports PMTUD via ICMP PTB for UDP.
// return value:
//   []: res, rlen1, rdf1*10+rmf1, nhmtu1, rlen2, rdf2*10+rmf2
func GetPmtudByUdp(ip, domain string, port uint16, spoof bool) []int {
	c, rc := CreateRawConn("udp")
	defer c.Close()
	defer rc.Close()
	rawFd := CreateRawFd()
	defer syscall.Close(rawFd)

	localIP := GetLocalIP()
	extIP := net.ParseIP(ip).To4()
	localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
	txid := uint16(rand.Int()) & 0xffff
	mtus := make([]int, 6, 6)

	// 1st DNS Query, MTU=1500
	ok := SendUdpByRawConn(rc, localIP, extIP, localPort, port, txid, 65535, domain, "ANY", 1)
	if ok == -1 {
		mtus[0] = -15
		return mtus
	}
	// 1st DNS Reply
	rdf1, rmf1, rlen1, _, _, rp1 := RecvByRawFd(rawFd, ip, localPort, txid)
	
	if rdf1 == -1 {
		mtus[0] = -14
		return mtus
	}
	mtus[1] = rlen1
	mtus[2] = rmf1 * 10 + rdf1
	if rdf1 == 0 && rmf1 == 0 {
		mtus[0] = -2
		return mtus
	}
	// ICMP PTB
	nhmtu := 68
	mtus[3] = nhmtu
	srcIP := localIP
	if spoof { 
		//srcIP = GetNeighbour(ip) 
		srcIP = GetSpoofedIP(ip, domain) 
	}
	
	ok = SendIcmpByRawConn(nil, srcIP, extIP, []uint16{3*256+4, txid, uint16(nhmtu)}, 1, rp1)
	if ok == -1 {
		mtus[0] = -13
		return mtus
	}
	// 2nd DNS Query, MTU=68
	ok = SendUdpByRawConn(rc, localIP, extIP, localPort, port, txid, 65535, domain, "ANY", 1)
	if ok == -1 {
		mtus[0] = -12
		return mtus
	}
	// 2nd DNS Reply
	rdf2, rmf2, rlen2, _, _, _ := RecvByRawFd(rawFd, ip, localPort, txid)
	if rdf2 == -1 {
		mtus[0] = -11
		return mtus
	}
	mtus[4] = rlen2
	mtus[5] = rmf2 * 10 + rdf2
	if (rlen2 < rlen1) || (rdf1 == 1 && rdf2 == 0) {
		mtus[0] = 0
	} else {
		mtus[0] = -1
	}
	return mtus
}
	//sm.RLock()
