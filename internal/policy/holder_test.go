package policy

import (
	"sync"
	"testing"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
)

func TestHolderSwapKeepsRateBudget(t *testing.T) {
	y := "rules:\n- name: r\n  who: {token: b}\n  hosts: {all: true}\n  tools: [ps]\n  rate: 1/hour\n"
	p1, err := Parse([]byte(y), tools)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHolder(p1)
	bot := identity.Identity{Kind: identity.KindBot, Name: "b"}
	host := inventory.Host{ID: "h"}
	if !h.Load().Check(bot, host, "ps").Allow {
		t.Fatal("first call refused")
	}
	p2, _ := Parse([]byte(y), tools)
	h.Swap(p2)
	if h.Load() != p2 {
		t.Fatal("swap did not take effect")
	}
	if h.Load().Check(bot, host, "ps").Allow {
		t.Fatal("swap reset the rate budget")
	}
}

func TestHolderConcurrent(t *testing.T) {
	p, _ := Parse([]byte(sample), tools)
	h := NewHolder(p)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = h.Load().Check(oncall, prod, "ps")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				np, _ := Parse([]byte(sample), tools)
				h.Swap(np)
			}
		}()
	}
	wg.Wait()
}
