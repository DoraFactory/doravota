package cli

import (
	"testing"

	"cosmossdk.io/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertDORAToPeakaPrecision tests the precision of DORA to peaka conversion
func TestConvertDORAToPeakaPrecision(t *testing.T) {
	testCases := []struct {
		name           string
		doraInput      string
		expectedPeaka  string
		expectError    bool
		errorContains  string
	}{
		{
			name:          "1 DORA",
			doraInput:     "1",
			expectedPeaka: "1000000000000000000", // 10^18
			expectError:   false,
		},
		{
			name:          "0.5 DORA",
			doraInput:     "0.5",
			expectedPeaka: "500000000000000000", // 0.5 * 10^18
			expectError:   false,
		},
		{
			name:          "smallest unit - 1 wei",
			doraInput:     "0.000000000000000001",
			expectedPeaka: "1", // 1 wei in peaka
			expectError:   false,
		},
		{
			name:          "maximum precision - 18 decimal places",
			doraInput:     "123.123456789123456789",
			expectedPeaka: "123123456789123456789", // Exact conversion
			expectError:   false,
		},
		{
			name:          "large integer",
			doraInput:     "1000000",
			expectedPeaka: "1000000000000000000000000", // 10^6 * 10^18
			expectError:   false,
		},
		{
			name:          "zero",
			doraInput:     "0",
			expectedPeaka: "0",
			expectError:   false,
		},
		{
			name:          "zero with decimals",
			doraInput:     "0.000000000000000000",
			expectedPeaka: "0",
			expectError:   false,
		},
		{
			name:          "too many decimal places",
			doraInput:     "1.0000000000000000001", // 19 decimal places
			expectError:   true,
			errorContains: "too many decimal places",
		},
		{
			name:          "invalid decimal format",
			doraInput:     "1.2.3",
			expectError:   true,
			errorContains: "invalid decimal format",
		},
		{
			name:          "invalid characters",
			doraInput:     "abc",
			expectError:   true,
			errorContains: "invalid integer part",
		},
		{
			name:          "negative number",
			doraInput:     "-1",
			expectError:   true,
			errorContains: "invalid integer part",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := convertDORAToPeaka(tc.doraInput)

			if tc.expectError {
				require.Error(t, err, "Expected error for input: %s", tc.doraInput)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error should contain expected text")
				}
			} else {
				require.NoError(t, err, "Unexpected error for input: %s", tc.doraInput)
				
				expected, ok := math.NewIntFromString(tc.expectedPeaka)
				require.True(t, ok, "Failed to parse expected peaka amount: %s", tc.expectedPeaka)
				assert.True(t, result.Equal(expected), 
					"Expected %s peaka, got %s peaka for input %s", 
					tc.expectedPeaka, result.String(), tc.doraInput)
			}
		})
	}
}

// TestPrecisionConsistency verifies that our implementation is consistent with mathematical expectations
func TestPrecisionConsistency(t *testing.T) {
	// Test that 0.1 + 0.2 = 0.3 (a classic floating point precision issue)
	result1, err := convertDORAToPeaka("0.1")
	require.NoError(t, err)
	
	result2, err := convertDORAToPeaka("0.2")
	require.NoError(t, err)
	
	result3, err := convertDORAToPeaka("0.3")
	require.NoError(t, err)
	
	sum := result1.Add(result2)
	assert.True(t, sum.Equal(result3), 
		"0.1 DORA + 0.2 DORA should equal 0.3 DORA: %s + %s = %s, expected %s",
		result1.String(), result2.String(), sum.String(), result3.String())
}

// TestEdgeCases tests edge cases that might cause issues
func TestEdgeCases(t *testing.T) {
	// Test very large number
	t.Run("very large number", func(t *testing.T) {
		_, err := convertDORAToPeaka("999999999999999999") // Close to uint64 max for integer part
		assert.NoError(t, err, "Should handle large integers within uint64 range")
	})
	
	// Test many small decimals that sum to 1
	t.Run("accumulation test", func(t *testing.T) {
		// 1000 * 0.001 should equal 1
		small, err := convertDORAToPeaka("0.001")
		require.NoError(t, err)
		
		one, err := convertDORAToPeaka("1")
		require.NoError(t, err)
		
		// Multiply small by 1000
		accumulated := small.MulRaw(1000)
		assert.True(t, accumulated.Equal(one), 
			"1000 * 0.001 DORA should equal 1 DORA: %s * 1000 = %s, expected %s",
			small.String(), accumulated.String(), one.String())
	})
}