package credentials

import (
	"fmt"
	"testing"
	"time"
)

type testAction struct {
	Fired bool
}

func (t *testAction) Do() error {
	t.Fired = true
	return nil
}

type testRenewable struct {
	RenewCount  uint
	MaxRenewals uint
}

func (t *testRenewable) Renew() error {
	if t.RenewCount >= t.MaxRenewals {
		return fmt.Errorf("Max renewals exceeded")
	}
	t.RenewCount++
	return nil
}

func (t *testRenewable) MaxRenewInterval() time.Duration {
	return 50 * time.Millisecond
}

func (t *testRenewable) String() string {
	return fmt.Sprintf("Renewed %d times", t.RenewCount)
}

func TestRenewer(t *testing.T) {
	test := &testRenewable{MaxRenewals: 5}
	action := &testAction{}
	renewer := NewCredentialRenewer(test, action)
	renewer.Renew()
	for renewCount := 0; renewCount < 5; {
		select {
		case renewal := <-renewer.RenewCh():
			t.Logf("Renewed: %s", renewal)
			if !action.Fired {
				t.Errorf("Post renew action didn't fire")
			}
			action.Fired = false
			renewCount++
		case err := <-renewer.DoneCh():
			if err != nil {
				t.Errorf("Renewer failed: %v", err)
			}
		}
	}
	renewer.Stop()
	if test.RenewCount < 5 {
		t.Errorf("Renewer didn't renew enough")
	}

}

func TestRenewerMerger(t *testing.T) {
	m := &RenewerMerger{}
	test := &testRenewable{MaxRenewals: 1}
	action := &testAction{}
	renewer := NewCredentialRenewer(test, action)
	m.AddRenewer(renewer)
	renewer.Renew()
	select {
	case out := <-m.RenewCh():
		t.Log(out)
	case err := <-m.DoneCh():
		t.Errorf("Unexpected error on first renewal: %v", err)
	}
	select {
	case out := <-m.RenewCh():
		t.Errorf("Unexpectedly renewed credential: %v", out)
	case err := <-m.DoneCh():
		t.Logf("Expected: %v", err)
	}
}
