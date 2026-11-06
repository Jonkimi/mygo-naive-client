package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type ServerOptions struct {
	BindAddr string
	Resolver *Resolver
}

type Server struct {
	opts       ServerOptions
	udpServer  *dns.Server
	tcpServer  *dns.Server
	udpConn    net.PacketConn
	tcpLn      net.Listener
	udpAddr    string
	tcpAddr    string
	closed     atomic.Bool
	wg         sync.WaitGroup
}

func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Resolver == nil {
		return nil, errors.New("resolver is required")
	}
	if opts.BindAddr == "" {
		opts.BindAddr = "127.0.0.1:53"
	}
	return &Server{opts: opts}, nil
}

func (s *Server) Start() error {
	udpConn, err := net.ListenPacket("udp", s.opts.BindAddr)
	if err != nil {
		return err
	}
	s.udpConn = udpConn
	s.udpAddr = udpConn.LocalAddr().String()

	tcpLn, err := net.Listen("tcp", s.udpAddr)
	if err != nil {
		_ = udpConn.Close()
		return err
	}
	s.tcpLn = tcpLn
	s.tcpAddr = tcpLn.Addr().String()

	s.udpServer = &dns.Server{
		PacketConn: s.udpConn,
		Handler:    s,
	}

	s.tcpServer = &dns.Server{
		Listener: s.tcpLn,
		Handler:  s,
	}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		_ = s.udpServer.ActivateAndServe()
	}()
	go func() {
		defer s.wg.Done()
		_ = s.tcpServer.ActivateAndServe()
	}()

	return nil
}

func (s *Server) Stop() error {
	if s.closed.Swap(true) {
		return nil
	}

	if s.udpServer != nil {
		_ = s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		_ = s.tcpServer.Shutdown()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) UDPAddr() string {
	return s.udpAddr
}

func (s *Server) TCPAddr() string {
	return s.tcpAddr
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	resp, err := s.opts.Resolver.ResolveMsg(ctx, r)
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	_ = w.WriteMsg(resp)
}
