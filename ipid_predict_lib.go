package ipid_predict_lib

import (
	"net"
	"time"
	"golang.org/x/net/ipv4"
	"math/rand"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	
	"strings"
	"sync"
	"bufio"
	"os"
	"strconv"

	//"fmt"
	
)

const TIMEOUT = 2000 * time.Millisecond

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
		Window: 29200,
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

	wiph := &ipv4.Header{
		Version:	ipv4.Version,
		Len:		ipv4.HeaderLen,
		TOS:		0,
		TotalLen:	ipv4.HeaderLen + len(wb),
		ID:			0,
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
	timeout := 1000 * time.Millisecond //2000
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


func RscanIpidVelocityTestIPV3(sip0, sip1, ip string, proto string, port uint16, domain, flag string, fs, sl int) (int, []int, []int64) {
	ids := []int{}
	times := make([]int64, 0)
	code := 0
	prob_rate := fs
	probes := sl
	
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
			//localIP := net.ParseIP("104.128.64.210").To4()
			localIP := net.ParseIP(sip0).To4()
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
				//_, riph = RscanSendIpidByUdp(localIP, extIP, port, timeout)
				
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
				//riph, _ = RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil) // Use Xiang's method 
				riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "udp", 0, nil, timeout)
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
			//localIP := net.ParseIP("104.128.64.242").To4()
			localIP := net.ParseIP(sip1).To4()
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
				//_, riph = RscanSendIpidByUdp(localIP, extIP, port, timeout)
				localPort := 10000 + (uint16(rand.Int()) & 0xffff) % 55535
				txid := uint16(rand.Int()) & 0xffff
				SendUdpByRawConn(nil, localIP, extIP, localPort, port, txid, 65535, domain, "A", 1)
				//riph, _ = RecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "", 0, nil)
				riph,  _ = RscanRecvByRawConn(nil, extIP, localIP, port, localPort, txid, "udp", "", "udp", 0, nil, timeout)
			
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
		//time.Sleep(1000 * time.Millisecond)
		time.Sleep(time.Duration(1.0/float64(prob_rate)*1000)*time.Millisecond)
	} 
	wg.Wait()
	count_nega := 0
	for _, id := range ids {
		if id < 0 {
			count_nega++
		}
	}
	if float64(count_nega)/float64(len(ids)) > 0.25 { return -1, ids, times}
	return code, ids, times
}


