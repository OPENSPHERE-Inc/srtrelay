package auth

import (
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/voc/srtrelay/internal/metrics"
	"github.com/voc/srtrelay/stream"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var requestDurations = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace:                   metrics.Namespace,
		Subsystem:                   "auth",
		Name:                        "request_duration_seconds",
		Help:                        "A histogram of auth http request latencies.",
		Buckets:                     prometheus.DefBuckets,
		NativeHistogramBucketFactor: 1.1,
	},
	[]string{"url", "application"},
)

type HttpAuthCache struct {
	allowed bool
	expiry  time.Time
}

type httpAuth struct {
	config HTTPAuthConfig
	client *http.Client
	cacahe map[string]*HttpAuthCache
	gcTime time.Time
	mutex  sync.Mutex
}

type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	x, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(x)
	return nil
}

type HTTPAuthConfig struct {
	URL           string
	Application   string
	Timeout       Duration // Timeout for Auth request
	PasswordParam string   // POST Parameter containing stream passphrase
}

// NewHttpAuth creates an Authenticator with a HTTP backend
func NewHTTPAuth(authConfig HTTPAuthConfig) Authenticator {
	m := requestDurations.MustCurryWith(prometheus.Labels{"url": authConfig.URL, "application": authConfig.Application})
	return &httpAuth{
		config: authConfig,
		client: &http.Client{
			Timeout:   time.Duration(authConfig.Timeout),
			Transport: promhttp.InstrumentRoundTripperDuration(m, http.DefaultTransport),
		},
		cacahe: make(map[string]*HttpAuthCache),
		gcTime: time.Now().Add(5 * time.Minute),
	}
}

func GCAuthCache(cache map[string]*HttpAuthCache) {
	for key, value := range cache {
		if value.expiry.Before(time.Now()) {
			delete(cache, key)
		}
	}
}

// Implement Authenticator

// Authenticate sends form-data in a POST-request to the configured url.
// If the response code is 2xx the publish/play is allowed, otherwise it is denied.
// This should be compatible with nginx-rtmps on_play/on_publish directives.
// https://github.com/arut/nginx-rtmp-module/wiki/Directives#on_play
func (h *httpAuth) Authenticate(streamid stream.StreamID) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Garbage collect cache every 5 minutes
	if h.gcTime.Before(time.Now()) {
		GCAuthCache(h.cacahe)
		h.gcTime = time.Now().Add(5 * time.Minute)
	}
	// Caching results for 5 seconds when failed, 5 minutes when successful
	if cache, ok := h.cacahe[streamid.String()]; ok {
		if cache.expiry.After(time.Now()) {
			return cache.allowed
		}
	}

	response, err := h.client.PostForm(h.config.URL, url.Values{
		"call":                 {streamid.Mode().String()},
		"app":                  {h.config.Application},
		"name":                 {streamid.Name()},
		"username":             {streamid.Username()},
		h.config.PasswordParam: {streamid.Password()},
	})
	if err != nil {
		log.Println("http-auth:", err)
		return false
	}
	defer response.Body.Close()

	res := true
	expiry := time.Now().Add(5 * time.Minute)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		res = false
		expiry = time.Now().Add(5 * time.Second)
	}

	h.cacahe[streamid.String()] = &HttpAuthCache{
		allowed: res,
		expiry:  expiry,
	}

	return res
}
