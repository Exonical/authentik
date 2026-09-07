package kerberos

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kkdcp"
)

func TestKKDCPHandlerPathAndBackend(t *testing.T) {
	var received []byte
	handler := &kkdcp.Handler{
		Backend: func(_ context.Context, message []byte) ([]byte, error) {
			received = append([]byte(nil), message...)
			return message, nil
		},
		RequireTargetURL: "/KdcProxy",
	}
	request, err := kkdcp.Encode([]byte("request"), "EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/", "/KdcProxy"} {
		req := httptest.NewRequest(http.MethodPost, "http://kdc.test"+path, bytes.NewReader(request))
		req.Header.Set("Content-Type", kkdcp.ContentType)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if path == "/KdcProxy" {
			if recorder.Code != http.StatusOK || !bytes.Equal(received, []byte("request")) {
				t.Fatalf("KKDCP request status=%d backend=%q", recorder.Code, received)
			}
		} else if recorder.Code != http.StatusNotFound {
			t.Fatalf("KKDCP path status=%d, want %d", recorder.Code, http.StatusNotFound)
		}
	}
}
