package types

import (
    "testing"
    "github.com/stretchr/testify/require"
)

func TestPolicyTicketKeyFormat(t *testing.T) {
    k := GetPolicyTicketKey("contract1", "user1", "digestXYZ")
    require.Equal(t, append(append(append(append(append(PolicyTicketKeyPrefix, []byte("contract1")...), '/'), []byte("user1")...), '/'), []byte("digestXYZ")...), k)
}
