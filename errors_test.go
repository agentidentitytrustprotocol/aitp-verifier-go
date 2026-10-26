package aitpverifier

import "testing"

func TestErrorCodes(t *testing.T) {
	info, ok := CodeInvalidSignature.Info()
	if !ok || info.Draft || info.Retryable || !info.RetryableStated {
		t.Fatalf("INVALID_SIGNATURE: %+v %v", info, ok)
	}
	if info, ok := CodeTimestampExpired.Info(); !ok || !info.Retryable {
		t.Fatal("TIMESTAMP_EXPIRED is retryable")
	}
	if info, ok := CodeBundleExpired.Info(); !ok || !info.Draft {
		t.Fatal("BUNDLE_EXPIRED is draft")
	}
	if _, ok := ErrorCode("UNSUPPORTED_ALGORITHM").Info(); ok {
		t.Fatal("the registry has no UNSUPPORTED_ALGORITHM")
	}
}
