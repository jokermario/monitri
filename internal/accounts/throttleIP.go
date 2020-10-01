package accounts
//
//import (
//"fmt"
//routing "github.com/go-ozzo/ozzo-routing/v2"
//"github.com/gomodule/redigo/redis"
//"log"
//"net"
//"net/http"
//"sync"
//"time"
//)
//
//func ThrottleIP(service2 Service, conn redis.Conn) routing.Handler {
//	return func(c *routing.Context) error {
//		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
//
//		if err != nil {
//			log.Println(err.Error())
//			return routing.NewHTTPError(http.StatusInternalServerError)
//		}
//		getVisitorIPAddress(ip)
//		bannedIpAddresses := make(chan string)
//		wg := sync.WaitGroup{}
//		wg.Add(1)
//		go banVisitorsIP(bannedIpAddresses)
//		go banIP(bannedIpAddresses, service2, conn)
//		wg.Wait()
//
//		return routing.NewHTTPError(http.StatusRequestTimeout)
//	}
//}
//
//// Create a custom visitorIPBehaviour struct which holds the ip request metadata for each user.
//type visitorIPBehaviour struct {
//	ipAddress string
//	requestCount int8
//	lastSeen time.Time
//}
//
//// Change the the map to hold values of the type visitorIPBehaviour.
//var visitorsIP = make(map[string]*visitorIPBehaviour)
//var visitorsIPToBan = make(map[string]string)
//var mut sync.Mutex
//
////func init()  {
//
////	bannedIpAddresses := make(chan string)
////	go banVisitorsIP(bannedIpAddresses)
////}
//
//func getVisitorIPAddress(ip string) {
//	mut.Lock()
//	defer mut.Unlock()
//
//	vi, exists := visitorsIP[ip]
//	if !exists {
//		var count int8 = 1
//		// Include the current time when creating a new visitor.
//		visitorsIP[ip] = &visitorIPBehaviour{ip, count, time.Now()}
//	}
//	// Update the last seen time for the visitor.
//	fmt.Println(visitorsIP[ip])
//	vi.requestCount = vi.requestCount + 1
//	vi.lastSeen = time.Now()
//}
//
//// Every minute check the map for visitors that haven't been seen for
//// more than 3 minutes and delete the entries.
//func banVisitorsIP(out chan<- string) {
//
//	for {
//		time.Sleep(5 * time.Second)
//		mut.Lock()
//		for ip, vi := range visitorsIP {
//			if vi.requestCount >= 3 && time.Since(vi.lastSeen) <= 8 * time.Second {
//				out <- ip
//				//_ = service2.flagIP(conn, ip)
//				//delete(visitors, ip)
//			}
//		}
//		for v := range visitorsIPToBan{
//			fmt.Println("ip to ban "+v)
//		}
//		mut.Unlock()
//	}
//}
////
//func banIP(ipsToBan <-chan string, service2 Service, conn redis.Conn) {
//	mut.Lock()
//	for v := range ipsToBan {
//		_ = service2.flagIP(conn, v)
//	}
//	mut.Unlock()
//}