package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingHeaders   = errors.New("missing X-Signature-256 or X-Timestamp")
	ErrInvalidTimestamp = errors.New("invalid X-Timestamp")
	ErrTimestampSkew    = errors.New("timestamp outside replay window")
	ErrBadSignature     = errors.New("hmac signature mismatch")
)

type Auth struct {
	secret  []byte
	maxSkew time.Duration
	nowUTC  func() time.Time
}

func NewAuth(secret string, maxSkew time.Duration) *Auth {
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	return &Auth{
		secret:  []byte(secret),
		maxSkew: maxSkew,
		nowUTC:  func() time.Time { return time.Now().UTC() },
	}
}

func Sign(secret []byte, unixTS int64, body []byte) string {
	h := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(h, "%d.", unixTS)
	_, _ = h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (a *Auth) Verify(sigHeader, tsHeader string, body []byte) error {
	if sigHeader == "" || tsHeader == "" {
		return ErrMissingHeaders
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}
	// Evaluate strictly in UTC unix seconds so local DST transitions never shift the replay window.
	now := a.nowUTC().Unix()
	if math.Abs(float64(now-ts)) > a.maxSkew.Seconds() {
		return ErrTimestampSkew
	}
	want := Sign(a.secret, ts, body)
	if !hmac.Equal([]byte(want), []byte(strings.TrimSpace(sigHeader))) {
		return ErrBadSignature
	}
	return nil
}
