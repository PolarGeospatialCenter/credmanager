package credentials

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type RenewableCredential interface {
	Renew() error
	MaxRenewInterval() time.Duration
	fmt.Stringer
}

type PostRenewAction interface {
	Do() error
}

type RenewOutput struct {
	Source      fmt.Stringer
	Message     string
	RenewalTime time.Time
}

func (o *RenewOutput) String() string {
	if o.Message != "" {
		return fmt.Sprintf("%s -- %s at %s", o.Source, o.Message, o.RenewalTime)
	}
	return fmt.Sprintf("%s renewed at: %s", o.Source, o.RenewalTime)
}

type renewTimer struct {
	*time.Timer
	failCount uint
	maxFail   uint
}

func newRenewTimer(d time.Duration, maxFail uint) *renewTimer {
	t := &renewTimer{}
	t.Timer = time.NewTimer(t.getInterval(d))
	t.maxFail = maxFail
	return t
}

func (t *renewTimer) getInterval(max time.Duration) time.Duration {
	return max / time.Duration(2<<t.failCount)
}

func (t *renewTimer) FailReset(d time.Duration) {
	if t.failCount < t.maxFail {
		t.failCount++
	}
	log.Printf("Timer reset for failed renewal, next renewal in %s", t.getInterval(d))
	t.Timer.Reset(t.getInterval(d))
}

func (t *renewTimer) Reset(d time.Duration) {
	t.failCount = 0
	t.Timer.Reset(t.getInterval(d))
}

type CredentialRenewer struct {
	Credential  RenewableCredential
	Action      PostRenewAction
	renewCh     chan *RenewOutput
	doneCh      chan error
	stopCh      chan bool
	lastRenewal time.Time
}

func NewCredentialRenewer(cred RenewableCredential, action PostRenewAction) *CredentialRenewer {
	r := &CredentialRenewer{Credential: cred}
	r.renewCh = make(chan *RenewOutput, 100)
	r.doneCh = make(chan error, 100)
	r.stopCh = make(chan bool, 100)
	r.lastRenewal = time.Now()
	r.Action = action
	log.Printf("Returning credentialRenewer")
	return r
}

func (r *CredentialRenewer) DoneCh() <-chan error {
	return r.doneCh
}

func (r *CredentialRenewer) RenewCh() <-chan *RenewOutput {
	return r.renewCh
}

func (r *CredentialRenewer) Stop() {
	r.stopCh <- true
}

func (r *CredentialRenewer) Renew() {
	timer := newRenewTimer(r.Credential.MaxRenewInterval(), 5)
	var failCount uint
	failCount = 0
	go func() {
		for {
			select {
			case <-timer.C:
				err := r.Credential.Renew()
				if err != nil {
					r.doneCh <- err
					timer.FailReset(r.Credential.MaxRenewInterval())
					continue
				}

				if err == nil && r.Action != nil {
					actionErr := r.Action.Do()
					if actionErr != nil {
						r.doneCh <- fmt.Errorf("error while executing post renew action: %v", err)
						timer.FailReset(r.Credential.MaxRenewInterval())
						continue
					}
				}

				r.lastRenewal = time.Now()
				update := &RenewOutput{RenewalTime: r.lastRenewal, Source: r.Credential}
				r.renewCh <- update
				failCount = 0
				timer.Reset(r.Credential.MaxRenewInterval())
			case stop := <-r.stopCh:
				if stop {
					return
				}
			}
		}
	}()
}

type Renewer interface {
	DoneCh() <-chan error
	RenewCh() <-chan *RenewOutput
}

type RenewerMerger struct {
	renewCh []<-chan *RenewOutput
	doneCh  []<-chan error
}

func (l *RenewerMerger) AddRenewer(r Renewer) {
	l.renewCh = append(l.renewCh, r.RenewCh())
	l.doneCh = append(l.doneCh, r.DoneCh())
}

func (l *RenewerMerger) DoneCh() <-chan error {
	var wg sync.WaitGroup
	out := make(chan error)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(l.renewCh))
	for _, c := range l.doneCh {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (l *RenewerMerger) RenewCh() <-chan *RenewOutput {
	var wg sync.WaitGroup
	out := make(chan *RenewOutput)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan *RenewOutput) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(l.renewCh))
	for _, c := range l.renewCh {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
