package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type cniConfigTemplate struct {
	// PodCIDR is the cidr for pods on the node.
	PodCIDR string
	// PodCIDRRanges is the cidr ranges for pods on the node.
	PodCIDRRanges []string
	// Routes is a list of routes configured.
	Routes []string
}

const (
	cniConfigFileName = "20-portod-net.conflist"
)

func writeCNIConfig(dir, tmpl string, data cniConfigTemplate) error {
	t, err := template.New("cni-config").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("parse CNI config template: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	cfgFile := filepath.Join(dir, cniConfigFileName)
	f, err := os.Create(cfgFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	if err := t.Execute(f, data); err != nil {
		return fmt.Errorf("generate cni config file %q: %w", cfgFile, err)
	}
	return err
}

func parsePodCIDRs(cidrs []string) (data cniConfigTemplate, _ error) {
	const (
		// zeroCIDRv6 is the null route for IPv6.
		zeroCIDRv6 = "::/0"
		// zeroCIDRv4 is the null route for IPv4.
		zeroCIDRv4 = "0.0.0.0/0"
	)

	var (
		routes       = make([]string, 0, len(cidrs))
		hasV4, hasV6 bool
	)
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)

		cidr, err := netip.ParsePrefix(raw)
		if err != nil {
			return data, err
		}

		if cidr.Addr().Is4() {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if hasV4 {
		routes = append(routes, zeroCIDRv4)
	}
	if hasV6 {
		routes = append(routes, zeroCIDRv6)
	}

	if len(routes) == 0 {
		return data, errors.New("pod cidr list is empty")
	}

	return cniConfigTemplate{
		PodCIDR:       cidrs[0],
		PodCIDRRanges: cidrs,
		Routes:        routes,
	}, nil
}
