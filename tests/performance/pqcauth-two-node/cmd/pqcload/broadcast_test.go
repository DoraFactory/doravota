package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubmitTransactionRecordsAcceptedAndRejectedResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		code     uint32
		accepted bool
	}{
		{name: "accepted", code: 0, accepted: true},
		{name: "rejected", code: 11, accepted: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(response, `{"jsonrpc":"2.0","id":1,"result":{"code":%d,"codespace":"pqcauth","log":"result","hash":"ABC"}}`, test.code)
			}))
			defer server.Close()

			result := submitTransaction(server.Client(), server.URL, broadcastJob{
				line: 1,
				record: txRecord{
					Mode: "hybrid", Index: 7, Hash: "expected", TxBase64: "AA==",
				},
			})
			require.Equal(t, test.accepted, result.Accepted)
			require.Equal(t, test.code, result.Code)
			require.Equal(t, "pqcauth", result.Codespace)
			require.NotEmpty(t, result.Submitted)
			require.NotEmpty(t, result.Completed)
			require.GreaterOrEqual(t, result.LatencyUS, int64(0))
		})
	}
}

func TestPercentileInt64(t *testing.T) {
	values := []int64{1, 2, 3, 4, 5}
	require.Equal(t, int64(3), percentileInt64(values, 0.50))
	require.Equal(t, int64(5), percentileInt64(values, 0.99))
	require.Zero(t, percentileInt64(nil, 0.95))
}
