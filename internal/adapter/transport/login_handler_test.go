package transport

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestAuthenticationRateSourceUsesOnlyNetworkPeerIP(t *testing.T) {
	a := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}})
	b := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 65432}})
	b = metadata.NewIncomingContext(b, metadata.Pairs("x-forwarded-for", "198.51.100.1", "forwarded", "for=203.0.113.1"))
	if authenticationPeer(a) != "192.0.2.1" || authenticationPeer(b) != authenticationPeer(a) {
		t.Fatal("connection port or untrusted forwarding changed rate bucket")
	}
	if authenticationPeer(context.Background()) != "unknown-network-peer" {
		t.Fatal("missing peer must share bounded fallback")
	}
}
