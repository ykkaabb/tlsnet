package enroll

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"unicode"

	"github.com/ykkaabb/tlsnet/internal/config"
)

type WizardOptions struct {
	Input        io.Reader
	Output       io.Writer
	ReadPassword func(prompt string) (string, error)
	Hostname     string
}

type WizardResult struct {
	Config   *config.Config
	JoinCode string
}

func RunWizard(options WizardOptions) (*WizardResult, error) {
	if options.Input == nil || options.Output == nil {
		return nil, errors.New("wizard input and output are required")
	}
	reader := bufio.NewReader(options.Input)
	hostname := cleanNodeName(options.Hostname)
	if hostname == "" {
		hostname = "client"
	}
	role, err := prompt(reader, options.Output, "Role (relay/gateway/client)", "client")
	if err != nil {
		return nil, err
	}
	role = strings.ToLower(role)
	if role != "relay" && role != "gateway" && role != "client" {
		return nil, errors.New("role must be relay, gateway, or client")
	}
	var code JoinCode
	var encoded string
	if role == "relay" {
		serverHost, err := requiredPrompt(reader, options.Output, "Public server IP or DNS name")
		if err != nil {
			return nil, err
		}
		port, err := prompt(reader, options.Output, "Public TCP/UDP port", "443")
		if err != nil {
			return nil, err
		}
		network, err := prompt(reader, options.Output, "Network name", "tlsnet")
		if err != nil {
			return nil, err
		}
		cover, err := prompt(reader, options.Output, "Camouflage SNI/cover domain", "www.speedtest.cn")
		if err != nil {
			return nil, err
		}
		pool, err := prompt(reader, options.Output, "Virtual network CIDR", "10.91.0.0/24")
		if err != nil {
			return nil, err
		}
		homeNode, err := prompt(reader, options.Output, "Home gateway node name", "home")
		if err != nil {
			return nil, err
		}
		homeSubnet, err := prompt(reader, options.Output, "Home LAN subnet", "192.168.3.0/24")
		if err != nil {
			return nil, err
		}
		code = JoinCode{
			ServerAddress: net.JoinHostPort(serverHost, port), NetworkName: network, ServerName: cover,
			OverlayPool: pool, HomeNode: homeNode, HomeSubnet: homeSubnet,
		}
		encoded, err = code.Encode()
		if err != nil {
			return nil, err
		}
	} else {
		value, err := requiredPrompt(reader, options.Output, "Join code from the relay")
		if err != nil {
			return nil, err
		}
		code, err = Decode(value)
		if err != nil {
			return nil, err
		}
		encoded = value
	}
	defaultNode := hostname
	if role == "relay" {
		defaultNode = "server"
	} else if role == "gateway" {
		defaultNode = code.HomeNode
	}
	node, err := prompt(reader, options.Output, "Node name", defaultNode)
	if err != nil {
		return nil, err
	}
	lanInterface := ""
	if role == "gateway" {
		detected := detectInterface(code.HomeSubnet)
		lanInterface, err = prompt(reader, options.Output, "Home LAN interface", detected)
		if err != nil {
			return nil, err
		}
		if lanInterface == "" {
			return nil, errors.New("home LAN interface is required")
		}
	}
	password, err := readSecret(reader, options, "Network password: ")
	if err != nil {
		return nil, err
	}
	confirmation, err := readSecret(reader, options, "Confirm password: ")
	if err != nil {
		return nil, err
	}
	if password == "" || password != confirmation {
		return nil, errors.New("passwords are empty or do not match")
	}
	cfg, err := Build(role, node, password, lanInterface, code)
	if err != nil {
		return nil, err
	}
	return &WizardResult{Config: cfg, JoinCode: encoded}, nil
}

func prompt(reader *bufio.Reader, output io.Writer, label, defaultValue string) (string, error) {
	if defaultValue == "" {
		fmt.Fprintf(output, "%s: ", label)
	} else {
		fmt.Fprintf(output, "%s [%s]: ", label, defaultValue)
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = defaultValue
	}
	return value, nil
}

func requiredPrompt(reader *bufio.Reader, output io.Writer, label string) (string, error) {
	value, err := prompt(reader, output, label, "")
	if err == nil && value == "" {
		err = fmt.Errorf("%s is required", strings.ToLower(label))
	}
	return value, err
}

func readSecret(reader *bufio.Reader, options WizardOptions, label string) (string, error) {
	if options.ReadPassword != nil {
		return options.ReadPassword(label)
	}
	return prompt(reader, options.Output, strings.TrimSuffix(label, ": "), "")
}

func cleanNodeName(value string) string {
	value = strings.TrimSpace(value)
	return strings.Trim(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, value), "-")
}

func detectInterface(subnet string) string {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return ""
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	match := ""
	for _, current := range interfaces {
		if current.Flags&net.FlagUp == 0 || current.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := current.Addrs()
		for _, address := range addresses {
			parsed, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Contains(parsed.Addr()) {
				if match != "" && match != current.Name {
					return ""
				}
				match = current.Name
			}
		}
	}
	return match
}

func SystemHostname() string {
	value, _ := os.Hostname()
	return value
}
