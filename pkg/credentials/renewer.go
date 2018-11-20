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

type RenewTimer struct {
	*time.Timer
	jitterPercent        int64
	initialFailInterval  time.Duration
	defaultRenewalWindow time.Duration
	failCount            uint
}

func NewRenewTimer(initialDelay, expirationWindow, initialFailInterval time.Duration, jitterPercent int64) *RenewTimer {
	t := &RenewTimer{}
	if initialFailInterval <= time.Duration(0) {
		initialFailInterval = 1 * time.Second
	}
	t.initialFailInterval = initialFailInterval
	t.jitterPercent = jitterPercent

	if expirationWindow <= 0 {
		// negative or zero expiration windows are invalid, default to 24h and print a warning
		log.Printf("Warning: initial expiration window set to invalid value (%s).  Defaulting to 24h.", expirationWindow)
		expirationWindow = time.Hour * 24
	}
	t.defaultRenewalWindow = expirationWindow
	t.Timer = time.NewTimer(initialDelay)
	return t
}

func (t *RenewTimer) jitterWindowNanoseconds(interval time.Duration) int64 {
	return t.jitterPercent * interval.Nanoseconds() / 100
}

func (t *RenewTimer) getSplay(interval time.Duration) time.Duration {
	jitterWindowNs := t.jitterWindowNanoseconds(interval)
	randomSpreadNs := rand.Int63n(jitterWindowNs << 1)
	return time.Duration(randomSpreadNs-jitterWindowNs) * time.Nanosecond
}

func (t *RenewTimer) getInterval(expirationWindow time.Duration, failCount uint) time.Duration {
	if expirationWindow <= time.Duration(0) {
		expirationWindow = t.defaultRenewalWindow
	}

	var interval time.Duration
	if failCount == 0 {
		interval = expirationWindow / 2
	} else {
		interval = t.initialFailInterval * time.Duration(1<<(failCount-1))
	}
	return interval + t.getSplay(interval)
}

// FailReset resets the timer using the exponential backoff time and increments
// the failure count
func (t *RenewTimer) FailReset(expirationWindow time.Duration) {
	t.failCount++
	t.Timer.Reset(t.getInterval(expirationWindow, t.failCount))
}

// Reset resets the timer using the success interval
func (t *RenewTimer) Reset(expirationWindow time.Duration) {
	t.failCount = 0
	t.Timer.Reset(t.getInterval(expirationWindow, t.failCount))
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
	maxFail := uint(18)
	timer := NewRenewTimer(0, r.Credential.MaxRenewInterval(), 5*time.Second, 10)
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
