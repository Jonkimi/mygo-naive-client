package warp

import (
	"bytes"
	"context"
	"testing"
)

func TestVarintEncodeDecode(t *testing.T) {
	testCases := []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903}

	for _, val := range testCases {
		var buf bytes.Buffer
		writeVarint(&buf, val)

		got, err := readVarint(&buf)
		if err != nil {
			t.Fatalf("failed to decode varint for %d: %v", val, err)
		}
		if got != val {
			t.Errorf("varint mismatch: expected %d, got %d", val, got)
		}
	}
}

func TestConnectMASQUE_InvalidAccount(t *testing.T) {
	ctx := context.Background()
	_, err := ConnectMASQUE(ctx, nil, "127.0.0.1:443", nil, true, true)
	if err == nil {
		t.Errorf("expected error with nil account")
	}
}
