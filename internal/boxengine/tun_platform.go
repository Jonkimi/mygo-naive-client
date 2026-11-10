package boxengine

import (
	"context"
	"net/netip"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

type platformInterfaceStub struct{}

func (s *platformInterfaceStub) Initialize(networkManager adapter.NetworkManager) error {
	return nil
}

// UsePlatformAutoDetectInterfaceControl must be false: AutoDetectInterfaceControl
// below is a no-op, so delegating to it would leave outbound sockets unbound and
// let them follow the 0/1 TUN routes back into the TUN (routing loop, log flood).
// Returning false makes sing-box bind sockets to the default interface itself.
func (s *platformInterfaceStub) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (s *platformInterfaceStub) AutoDetectInterfaceControl(fd int) error {
	return nil
}

func (s *platformInterfaceStub) UsePlatformInterface() bool {
	return false
}

func (s *platformInterfaceStub) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	return nil
}

func (s *platformInterfaceStub) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func (s *platformInterfaceStub) CreateDefaultInterfaceMonitor(l logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}

func (s *platformInterfaceStub) UsePlatformNetworkInterfaces() bool {
	return false
}

func (s *platformInterfaceStub) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) UnderNetworkExtension() bool {
	return false
}

func (s *platformInterfaceStub) NetworkExtensionIncludeAllNetworks() bool {
	return false
}

func (s *platformInterfaceStub) ClearDNSCache() {}

func (s *platformInterfaceStub) RequestPermissionForWIFIState() error {
	return nil
}

func (s *platformInterfaceStub) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}

func (s *platformInterfaceStub) UsePlatformConnectionOwnerFinder() bool {
	return false
}

func (s *platformInterfaceStub) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) UsePlatformWIFIMonitor() bool {
	return false
}

func (s *platformInterfaceStub) UsePlatformNotification() bool {
	return false
}

func (s *platformInterfaceStub) SendNotification(notification *adapter.Notification) error {
	return nil
}

func (s *platformInterfaceStub) CancelNotification(identifier string, typeID int32) error {
	return nil
}

func (s *platformInterfaceStub) MyInterfaceAddress() []netip.Addr {
	return nil
}

func (s *platformInterfaceStub) UsePlatformNeighborResolver() bool {
	return false
}

func (s *platformInterfaceStub) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}

func (s *platformInterfaceStub) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}

func (s *platformInterfaceStub) UsePlatformShell() bool {
	return false
}

func (s *platformInterfaceStub) CheckPlatformShell() error {
	return nil
}

func (s *platformInterfaceStub) OpenShellSession(user *adapter.PlatformUser, command string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) LookupUser(username string) (*adapter.PlatformUser, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) LookupSFTPServer() (string, error) {
	return "", os.ErrInvalid
}

func (s *platformInterfaceStub) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) TailscaleHostname() string {
	return ""
}

func (s *platformInterfaceStub) UsePlatformBridge() bool {
	return false
}

func (s *platformInterfaceStub) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

// TunPlatform wraps a pre-opened TUN file descriptor and passes it into sing-tun.
type TunPlatform struct {
	platformInterfaceStub
	TunFD      int
	TunName    string
	TunCreator func(options tun.Options) (tun.Tun, error)
}

func (p *TunPlatform) UsePlatformInterface() bool {
	return p.TunFD > 0
}

func (p *TunPlatform) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	options.FileDescriptor = p.TunFD
	if p.TunName != "" {
		options.Name = p.TunName
	}
	if p.TunCreator != nil {
		return p.TunCreator(*options)
	}
	return tun.New(*options)
}
