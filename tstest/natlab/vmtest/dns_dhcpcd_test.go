// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
)

const (
	// The guest's vnet NIC, the one dhcpcd configures.
	dhcpcdNIC = "enp0s3"

	// The snippet dhcpcd's resolv.conf hook registers for the NIC's DHCP
	// lease: "<interface>.<protocol>".
	dhcpcdSnippet = dhcpcdNIC + ".dhcp"
)

// newDhcpcdEnv brings up a single Ubuntu node whose vnet NIC is configured
// by dhcpcd, with openresolv installed so dhcpcd's hook registers
// dhcpcdSnippet. The DNS config is the same as newOpenresolvEnv's.
func newDhcpcdEnv(t *testing.T) (*vmtest.Env, *vmtest.Node, *vnet.Network) {
	t.Helper()
	env := vmtest.New(t,
		vmtest.ControlDNS(orMagicDNSDomain, &tailcfg.DNSConfig{
			Proxied: true,
			Domains: []string{orLocalDomain},
			Routes: map[string][]*dnstype.Resolver{
				orLocalDomain: nil,
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: orLocalName, Type: "A", Value: orLocalIP},
			},
		}))
	nw := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	node := env.AddNode("node", nw,
		vmtest.OS(vmtest.Ubuntu2404),
		vmtest.WithDNSMode(vmtest.DNSOpenresolv),
		vmtest.WithDHCPClient(vmtest.DHCPClientDhcpcd))
	env.Start()

	env.AssertDNSBackend(node, "openresolv")
	assertDhcpcdLease(t, env, node, vnet.FakeDNSIPv4().String())
	return env, node, nw
}

// assertDhcpcdLease waits for dhcpcd, not networkd, to hold the vnet NIC's
// lease, with its hook having registered dhcpcdSnippet naming the given
// nameserver. The hook runs after dhcpcd has bound the address, so this
// may briefly lag a `dhcpcd -w` that has already returned.
func assertDhcpcdLease(t *testing.T, env *vmtest.Env, n *vmtest.Node, nameserver string) {
	t.Helper()
	cmd := "networkctl status " + dhcpcdNIC + " | grep -m1 State:; resolvconf -i; resolvconf -l " + dhcpcdSnippet
	var last string
	if err := tstest.WaitFor(15*time.Second, func() error {
		out, err := env.SSHExec(n, cmd)
		last = out
		if err != nil {
			return fmt.Errorf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
		}
		if !strings.Contains(out, "unmanaged") {
			return fmt.Errorf("networkd still manages %s", dhcpcdNIC)
		}
		if !slices.Contains(strings.Fields(out), dhcpcdSnippet) {
			return fmt.Errorf("resolvconf has no %s snippet", dhcpcdSnippet)
		}
		if !strings.Contains(out, "nameserver "+nameserver) {
			return fmt.Errorf("%s snippet does not name %s", dhcpcdSnippet, nameserver)
		}
		return nil
	}); err != nil {
		t.Fatalf("%v:\n%s", err, last)
	}
}

// TestDhcpcdOpenresolvDNS checks the dhcpcd provisioning itself: dhcpcd holds
// the lease, its hook registered the lease's nameserver with openresolv, and
// tailscaled forwards public names there.
func TestDhcpcdOpenresolvDNS(t *testing.T) {
	env, node, _ := newDhcpcdEnv(t)
	assertOpenresolvResolvConf(t, env, node,
		[]string{orSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()})
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)
}

// TestDhcpcdLeaseRebind checks that tailscaled picks up the DNS servers a
// DHCP lease carries when dhcpcd releases the lease and binds a new one.
// dhcpcd configures the address first and runs its resolv.conf hook
// afterwards; here the hook is slowed by a second so that order is certain.
// See tailscale/tailscale#21607.
func TestDhcpcdLeaseRebind(t *testing.T) {
	env, node, _ := newDhcpcdEnv(t)

	// A router-advertised nameserver that nothing answers. vnet sends no
	// router advertisements, so the snippet dhcpcd would register for one is
	// added by hand. It outlives the DHCP lease.
	addOpenresolvSnippet(t, env, node, dhcpcdNIC+".ra", orDeadNameserver)
	env.SetAcceptDNS(node, false)
	env.SetAcceptDNS(node, true)
	assertOpenresolvResolvConf(t, env, node,
		[]string{orSignature, orQuad100},
		[]string{vnet.FakeDNSIPv4().String()})
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)

	// Slow every hook run by a second, then release the lease: dhcpcd removes
	// the address, and the hook removes dhcpcdSnippet.
	cmd := fmt.Sprintf("printf 'sleep 1\\n' > %s && dhcpcd -k %s", vmtest.DhcpcdEnterHook, dhcpcdNIC)
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}
	if err := tstest.WaitFor(15*time.Second, func() error {
		out, err := env.SSHExec(node, "resolvconf -i")
		if err != nil {
			return err
		}
		if slices.Contains(strings.Fields(out), dhcpcdSnippet) {
			return fmt.Errorf("%s is still registered", dhcpcdSnippet)
		}
		return nil
	}); err != nil {
		t.Fatalf("release did not remove the snippet: %v", err)
	}

	// Count the resolver configs compiled so far, including the one the
	// address removal triggered. The rebind must add one.
	before := len(resolverCfgLogs(t, env, node))
	if before == 0 {
		t.Fatal("no Resolvercfg lines in tailscaled's log")
	}

	// Bind a new lease: dhcpcd adds the address, then the hook adds
	// dhcpcdSnippet back a second later.
	cmd = "dhcpcd -q -w " + dhcpcdNIC
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}
	assertDhcpcdLease(t, env, node, vnet.FakeDNSIPv4().String())

	// Some resolver config compiled since the rebind must include the
	// lease's nameserver.
	var since []string
	if err := tstest.WaitFor(60*time.Second, func() error {
		since = resolverCfgLogs(t, env, node)[before:]
		for _, line := range since {
			if strings.Contains(line, vnet.FakeDNSIPv4().String()) {
				return nil
			}
		}
		return fmt.Errorf("no resolver config since the rebind includes %s", vnet.FakeDNSIPv4())
	}); err != nil {
		t.Errorf("%v (tailscale/tailscale#21607); configs compiled since the rebind:\n%s",
			err, strings.Join(since, "\n"))
	}

	// Public names must still resolve.
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)
}

// TestDhcpcdRenewalChangesDNS checks that tailscaled picks up new DNS servers
// delivered by a lease renewal. The renewal keeps the address, so there is no
// netlink event; dhcpcd's hook re-registers dhcpcdSnippet with the new
// servers. See tailscale/tailscale#21607.
func TestDhcpcdRenewalChangesDNS(t *testing.T) {
	env, node, nw := newDhcpcdEnv(t)
	assertResolves(t, env, node, orUpstreamOnlyName, orUpstreamOnlyIP)

	// The DHCP server switches to a nameserver that answers only
	// vnet.SplitDNSName, and the client renews.
	nw.SetDHCPDNS(vnet.FakeSplitDNSIPv4())
	cmd := "dhcpcd -n " + dhcpcdNIC
	if out, err := env.SSHExec(node, cmd); err != nil {
		t.Fatalf("%s: %v (%s)", cmd, err, strings.TrimSpace(out))
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(node, "resolvconf -l "+dhcpcdSnippet)
		if err != nil {
			return err
		}
		if !strings.Contains(out, vnet.FakeSplitDNSIPv4().String()) {
			return fmt.Errorf("%s still reads:\n%s", dhcpcdSnippet, out)
		}
		return nil
	}); err != nil {
		t.Fatalf("renewal did not deliver the new nameserver: %v", err)
	}

	// tailscaled can read the new nameserver back.
	if base := openresolvBaseConfig(t, env, node); base != nil {
		if want := vnet.FakeSplitDNSIPv4().String(); !slices.Equal(base.Nameservers, []string{want}) {
			t.Fatalf("OS base config nameservers after renewal = %q, want just %s", base.Nameservers, want)
		}
	}

	// A name only the new nameserver answers must resolve through quad-100.
	assertResolves(t, env, node, vnet.SplitDNSName, vnet.SplitDNSAddr)
}
