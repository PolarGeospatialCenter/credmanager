package credentials

import (
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

type ErrMaxRetriesExceeded struct {
	MaxRetries uint
	Message    string
}

func (e ErrMaxRetriesExceeded) Error() string {
	return fmt.Sprintf("Exceeded maximum allowed retries (%d): %s", e.MaxRetries, e.Message)
}

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
	spreadPercent float64
	defaultWindow time.Duration
	failCount     uint
	maxFail       uint
}

func newRenewTimer(initialExpirationWindow time.Duration, maxFail uint) *renewTimer {
	t := &renewTimer{}
	if maxFail == 0 {
		maxFail = 3
	}
	t.spreadPercent = 0.10
	if initialExpirationWindow <= 0 {
		// negative or zero expiration windows are invalid, default to 24h and print a warning
		log.Printf("Warning: initial expiration window set to invalid value (%s).  Defaulting to 24h.", initialExpirationWindow)
		initialExpirationWindow = time.Hour * 24
	}
	t.defaultWindow = initialExpirationWindow
	t.maxFail = maxFail
	interval := initialExpirationWindow / 2
	spread := 2*t.getRandomSpreadInterval(interval) - t.getSpreadInterval(interval)
	t.Timer = time.NewTimer(interval + spread)
	return t
}

func (t *renewTimer) getRandomSpreadInterval(baseInterval time.Duration) time.Duration {
	if baseInterval < 0 {
		return time.Duration(0)
	}
	randomSpreadNs := rand.Int63n(int64(t.spreadPercent * float64(baseInterval.Nanoseconds())))
	return time.Duration(randomSpreadNs) * time.Nanosecond
}

func (t *renewTimer) getSpreadInterval(baseInterval time.Duration) time.Duration {
	return time.Duration(t.spreadPercent*float64(baseInterval.Nanoseconds())) * time.Nanosecond
}

func (t *renewTimer) getInterval(expirationWindow time.Duration) time.Duration {
	if expirationWindow <= 0 {
		expirationWindow = t.defaultWindow
	}
	expirationWindow = expirationWindow / 2
	baseDelay := expirationWindow / time.Duration(2<<t.maxFail)
	interval := baseDelay * time.Duration(2<<t.failCount)
	spread := 2*t.getRandomSpreadInterval(interval) - t.getSpreadInterval(interval)
	return interval + spread
}

func (t *renewTimer) FailReset(expirationWindow time.Duration) {
	if t.failCount < t.maxFail {
		t.failCount++
	}
	log.Printf("Timer reset for failed renewal, next renewal in %s", t.getInterval(expirationWindow))
	t.Timer.Reset(t.getInterval(expirationWindow))
}

func (t *renewTimer) Reset(expirationWindow time.Duration) {
	t.failCount = 0
	t.Timer.Reset(t.getInterval(expirationWindow))
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
	maxFail := uint(5)
	timer := newRenewTimer(r.Credential.MaxRenewInterval(), maxFail)
	var failCount uint
	failCount = 0
	go func() {
		for {
			select {
			case <-timer.C:
				err := r.Credential.Renew()
				if err != nil {
					r.doneCh <- fmt.Errorf("error renewing %s: %v", r.Credential.String(), err)
					if failCount > maxFail {
						r.doneCh <- ErrMaxRetriesExceeded{MaxRetries: maxFail, Message: fmt.Sprintf("credential: %s", r.Credential)}
					}
					timer.FailReset(r.Credential.MaxRenewInterval())
					continue
				} else if r.Action != nil {
					actionErr := r.Action.Do()
					if actionErr != nil {
						r.doneCh <- fmt.Errorf("error while executing post renew action: %v", actionErr)
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
	r       <-chan *RenewOutput
	d       <-chan error
}

func (l *RenewerMerger) AddRenewer(r Renewer) {
	l.renewCh = append(l.renewCh, r.RenewCh())
	l.doneCh = append(l.doneCh, r.DoneCh())
}

func (l *RenewerMerger) makeDoneCh() <-chan error {
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
	wg.Add(len(l.doneCh))
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

func (l *RenewerMerger) DoneCh() <-chan error {
	if l.d == nil {
		l.d = l.makeDoneCh()
	}
	return l.d
}

func (l *RenewerMerger) makeRenewCh() <-chan *RenewOutput {
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

func (l *RenewerMerger) RenewCh() <-chan *RenewOutput {
	if l.r == nil {
		l.r = l.makeRenewCh()
	}
	return l.r
}
