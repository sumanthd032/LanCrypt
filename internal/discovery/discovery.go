package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// ServiceName is the unique identifier for the LanCrypt mDNS service.
	ServiceName = "_lancrypt._tcp"
	// Domain is the network domain, "local" is standard for mDNS.
	Domain = "local"
)

// PublishService advertises the LanCrypt service on the network.
// It takes the unique instance name (the code) and the rendezvous port.
func PublishService(instance string, port int) (*zeroconf.Server, error) {
	server, err := zeroconf.Register(
		instance,       // The unique name for this instance (e.g., "kite-yacht-ninja")
		ServiceName,    // The service type
		Domain,         // The domain
		port,           // The port the service is running on (our rendezvous port)
		[]string{"txtv=0", "lo=1", "la=2"}, // Optional metadata
		nil,            // Network interfaces to use (nil for all)
	)
	if err != nil {
		return nil, fmt.Errorf("could not register mDNS service: %w", err)
	}
	fmt.Printf("mDNS service '%s' published on port %d\n", instance, port)
	return server, nil
}

// DiscoverService browses the network to find a LanCrypt service with a specific instance name.
func DiscoverService(instance string) (*zeroconf.ServiceEntry, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize mDNS resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5) // 5-second timeout
	defer cancel()

	// The Browse function now takes the channel as an argument.
	err = resolver.Browse(ctx, ServiceName, Domain, entries)
	if err != nil {
		return nil, fmt.Errorf("failed to browse for services: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("could not find sender '%s' on the network (timeout)", instance)
		case entry := <-entries:
			if entry.Instance == instance {
				// We found our specific instance.
				var ipv4 net.IP
				for _, addr := range entry.AddrIPv4 {
					// Prefer a non-loopback, global unicast address.
					if addr.IsGlobalUnicast() && !addr.IsLoopback() {
						ipv4 = addr
						break
					}
				}
				if ipv4 == nil && len(entry.AddrIPv4) > 0 {
					// Fallback to the first available IPv4 address if no ideal one is found.
					ipv4 = entry.AddrIPv4[0]
				}

				if ipv4 == nil {
					return nil, fmt.Errorf("found sender but it has no usable IPv4 address")
				}
				// Replace the IP in the entry for consistency.
				entry.AddrIPv4 = []net.IP{ipv4}
				return entry, nil
			}
		}
	}
}