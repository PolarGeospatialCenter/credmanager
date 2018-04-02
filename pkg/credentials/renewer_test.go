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
	RenewCount uint
}

func (t *testRenewable) Renew() error {
	t.RenewCount += 1
	return nil
}

func (t *testRenewable) MaxRenewInterval() time.Duration {
	return 50 * time.Millisecond
}

func (t *testRenewable) String() string {
	return fmt.Sprintf("Renewed %d times", t.RenewCount)
}

func TestRenewer(t *testing.T) {
	test := &testRenewable{}
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
