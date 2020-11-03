package accounts

import (
	routing "github.com/go-ozzo/ozzo-routing/v2"
	"golang.org/x/time/rate"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

//RateHandler returns a handler that handles rate limiting
func RateHandler() routing.Handler {
	return func(c *routing.Context) error {
		ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)

		if err != nil {
			log.Println(err.Error())
			return routing.NewHTTPError(http.StatusInternalServerError)
		}
		limiter := getVisitor(ip)
		if !limiter.Allow() {
			return routing.NewHTTPError(http.StatusTooManyRequests)
		}
		return nil
	}
}

// creates a custom visitor struct which holds the rate limiter for each
// visitor and the last time that the visitor was seen.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Change the the map to hold values of the type visitor.
var visitors = make(map[string]*visitor)
var mu sync.Mutex

// Run a background goroutine to remove old entries from the visitors map.
func init() {
	go cleanupVisitors()
}

func getVisitor(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	v, exists := visitors[ip]
	if !exists {
		//todo remember to increase the request burst size to a reasonable amount depending on my server e.g(200-300)
		limiter := rate.NewLimiter(1, 3)
		// Include the current time when creating a new visitor.
		visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}
	// Updates the last seen time for the visitor.
	v.lastSeen = time.Now()
	return v.limiter
}

// Every minute check the map for visitors that haven't been seen for
// more than 3 minutes and delete the entries.
func cleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		mu.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}