package directpair

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpService struct {
	Type    string `xml:"serviceType"`
	Control string `xml:"controlURL"`
}

func (d upnpDevice) wanService() (upnpService, bool) {
	for _, service := range d.Services {
		switch service.Type {
		case "urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANPPPConnection:1":
			return service, true
		}
	}
	for _, child := range d.Devices {
		if service, ok := child.wanService(); ok {
			return service, true
		}
	}
	return upnpService{}, false
}

func gatewayURL(u *url.URL, gateway netip.Addr) bool {
	return u != nil && u.Scheme == "http" && u.Hostname() == gateway.String() && u.User == nil
}

func discoverUPnP(ctx context.Context, local, gateway netip.Addr) (*url.URL, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local.AsSlice()})
	if err != nil {
		return nil, err
	}
	defer socket.Close()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	_ = socket.SetDeadline(time.Now().Add(1100 * time.Millisecond))
	targets := []netip.AddrPort{netip.AddrPortFrom(gateway, 1900), netip.MustParseAddrPort("239.255.255.250:1900")}
	for _, dest := range targets {
		search := "M-SEARCH * HTTP/1.1\r\nHOST: " + dest.String() + "\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
		_, _ = socket.WriteToUDPAddrPort([]byte(search), dest)
	}
	var buffer [4096]byte
	for {
		n, from, err := socket.ReadFromUDPAddrPort(buffer[:])
		if err != nil {
			return nil, err
		}
		if from.Addr().Unmap() != gateway {
			continue
		}
		for _, line := range strings.Split(string(buffer[:n]), "\n") {
			name, value, found := strings.Cut(line, ":")
			if found && strings.EqualFold(name, "location") {
				location, err := url.Parse(strings.TrimSpace(value))
				if err == nil && gatewayURL(location, gateway) {
					return location, nil
				}
			}
		}
	}
}

// A router may offer a UPnP description URL and a separate control URL.
// Both must point to the selected gateway, and redirects/proxies are disabled.
func upnpMapping(ctx context.Context, local, gateway netip.Addr, port uint16, nonce [12]byte) (mapping, error) {
	location, err := discoverUPnP(ctx, local, gateway)
	if err != nil {
		return mapping{}, err
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: local.AsSlice()}, Timeout: time.Second}
	transport := &http.Transport{DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 1200 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	read := func(request *http.Request) ([]byte, int, error) {
		response, err := client.Do(request)
		if err != nil {
			return nil, 0, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return body, response.StatusCode, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return mapping{}, err
	}
	data, status, err := read(request)
	var root struct {
		Device upnpDevice `xml:"device"`
	}
	if err != nil || status != 200 || xml.Unmarshal(data, &root) != nil {
		return mapping{}, errors.New("invalid UPnP gateway description")
	}
	service, ok := root.Device.wanService()
	if !ok {
		return mapping{}, errors.New("UPnP gateway has no WAN service")
	}
	control, err := location.Parse(service.Control)
	if err != nil || !gatewayURL(control, gateway) {
		return mapping{}, errors.New("invalid UPnP control URL")
	}
	soap := func(action, args string) ([]byte, int, error) {
		body := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + service.Type + `">` + args + `</u:` + action + `></s:Body></s:Envelope>`
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, control.String(), strings.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		req.Header.Set("SOAPAction", `"`+service.Type+"#"+action+`"`)
		return read(req)
	}
	data, status, err = soap("GetExternalIPAddress", "")
	var external struct {
		Address string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err != nil || status != 200 || xml.Unmarshal(data, &external) != nil {
		return mapping{}, errors.New("UPnP external address unavailable")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(external.Address))
	if err != nil || !ip.Is4() {
		return mapping{}, errors.New("invalid UPnP external address")
	}
	endpoint := netip.AddrPortFrom(ip, port)
	if !PublicEndpoint(endpoint) {
		return mapping{endpoint: endpoint}, nil
	}
	portText := strconv.Itoa(int(port))
	selection := `<NewRemoteHost></NewRemoteHost><NewExternalPort>` + portText + `</NewExternalPort><NewProtocol>UDP</NewProtocol>`
	description := "DirectLAN " + hex.EncodeToString(nonce[:])
	data, status, err = soap("GetSpecificPortMappingEntry", selection)
	var current struct {
		Description string `xml:"Body>GetSpecificPortMappingEntryResponse>NewPortMappingDescription"`
		Fault       int    `xml:"Body>Fault>detail>UPnPError>errorCode"`
	}
	if err != nil || xml.Unmarshal(data, &current) != nil || (status == 200 && current.Description != description) || (status != 200 && current.Fault != 714) {
		return mapping{}, errors.New("UPnP UDP port is occupied or cannot be inspected")
	}
	args := selection + `<NewInternalPort>` + portText + `</NewInternalPort><NewInternalClient>` + local.String() + `</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>` + description + `</NewPortMappingDescription><NewLeaseDuration>` + fmt.Sprint(mappingLifetime) + `</NewLeaseDuration>`
	_, status, err = soap("AddPortMapping", args)
	if err != nil || status != 200 {
		return mapping{}, errors.New("UPnP router refused a temporary UDP port")
	}
	return mapping{endpoint: endpoint, lifetime: mappingLifetime * time.Second}, nil
}
