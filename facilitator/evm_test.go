package facilitator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/rabbitprincess/x402-facilitator/evm"
	"github.com/rabbitprincess/x402-facilitator/types"
)

// MockEthClient is a mock implementation of the ethclient.ClientInterface (or relevant parts).
// For this test, we only need to mock PendingNonceAt.
// If EVMFacilitator.Verify starts using other client methods, they'll need to be added here.
type MockEthClient struct {
	mock.Mock
}

func (m *MockEthClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	args := m.Called(ctx, account)
	return args.Get(0).(uint64), args.Error(1)
}

// MockSigner is a mock implementation of evm.Signer.
// It's not strictly needed for these tests as Verify doesn't use the signer,
// but NewEVMFacilitator requires one.
type MockSigner struct {
	mock.Mock
}

func (m *MockSigner) Sign(data []byte) ([]byte, error) {
	args := m.Called(data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSigner) Address() common.Address {
	args := m.Called()
	return args.Get(0).(common.Address)
}

// mustNewEVMPayload is a helper to create an EVMPayload and marshal it to JSON string.
func mustNewEVMPayload(t *testing.T, fromAddress common.Address, nonce int64, value *big.Int, signature string) string {
	payload := evm.EVMPayload{
		Authorization: evm.EIP3009Authorization{
			From:        fromAddress,
			To:          common.HexToAddress("0xReceiverAddress"),
			Value:       value,
			ValidAfter:  big.NewInt(0),
			ValidBefore: big.NewInt(1), // Ensure deadline is valid if checked
			Nonce:       big.NewInt(nonce),
		},
		Signature: signature, // Placeholder, real signature verification is assumed to be tested elsewhere or handled before these checks
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal EVMPayload: %v", err)
	}
	return string(payloadBytes)
}

func TestEVMFacilitator_Verify(t *testing.T) {
	mockClient := new(MockEthClient)
	mockSigner := new(MockSigner)
	mockSigner.On("Address").Return(common.HexToAddress("0xFacilitatorSigner"))

	// Use a dummy private key for NewEVMFacilitator, it's not used by Verify if signer is mocked or not used
	facilitator, err := NewEVMFacilitator(types.EVM, "mock-url", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("Failed to create EVMFacilitator: %v", err)
	}
	facilitator.client = mockClient // Replace the real client with the mock

	fromAddr := common.HexToAddress("0xPayerAddress")
	validNonce := int64(10)
	validAmount := big.NewInt(2000000000000000)    // 0.002 * 10^18 (above 0.001 threshold)
	lowAmount := big.NewInt(100)                   // Below threshold
	placeholderSignature := "0x123456" // Signature check happens before nonce/amount checks

	// Define PaymentRequirements
	req := &types.PaymentRequirements{
		Scheme:  types.EVM,
		Network: "base-sepolia",
		Asset:   "0xUSDCAssetAddress", // Not directly used by these checks but good to have
	}

	// Pre-check: Ensure GetChainID works for "base-sepolia"
	chainID, ok := evm.GetChainID("base-sepolia")
	assert.True(t, ok, "GetChainID should find 'base-sepolia'")
	assert.Equal(t, big.NewInt(84532), chainID, "ChainID for 'base-sepolia' should be 84532")

	tests := []struct {
		name                string
		setupMock           func()
		payloadNonce        int64
		payloadAmount       *big.Int
		expectedIsValid     bool
		expectedInvalidReason string
		expectError         bool
	}{
		{
			name: "Valid Payload",
			setupMock: func() {
				mockClient.On("PendingNonceAt", mock.Anything, fromAddr).Return(uint64(validNonce), nil).Once()
			},
			payloadNonce:    validNonce,
			payloadAmount:   validAmount,
			expectedIsValid: true,
		},
		{
			name: "Invalid Nonce - Mismatch",
			setupMock: func() {
				mockClient.On("PendingNonceAt", mock.Anything, fromAddr).Return(uint64(validNonce+1), nil).Once()
			},
			payloadNonce:        validNonce,
			payloadAmount:       validAmount,
			expectedIsValid:     false,
			expectedInvalidReason: "invalid_nonce",
		},
		{
			name: "Invalid Nonce - Error Fetching Nonce",
			setupMock: func() {
				mockClient.On("PendingNonceAt", mock.Anything, fromAddr).Return(uint64(0), errors.New("rpc error")).Once()
			},
			payloadNonce:        validNonce,
			payloadAmount:       validAmount,
			expectedIsValid:     false,
			expectedInvalidReason: "failed to get nonce: rpc error", // Match the error formatting in evm.go
		},
		{
			name: "Invalid Amount - Too Low",
			setupMock: func() {
				mockClient.On("PendingNonceAt", mock.Anything, fromAddr).Return(uint64(validNonce), nil).Once()
			},
			payloadNonce:        validNonce,
			payloadAmount:       lowAmount,
			expectedIsValid:     false,
			expectedInvalidReason: "payment_value_too_low",
		},
		// Test case for scheme mismatch (existing check)
		{
			name: "Scheme Mismatch - Payload",
			setupMock: func() {
				// No client call expected
			},
			payloadNonce:    validNonce,
			payloadAmount:   validAmount,
			expectedIsValid: false,
			// This test will use a different scheme in payload
			expectedInvalidReason: fmt.Sprintf("Incompatible payload scheme. payload: other-scheme, paymentRequirements: %s, supported: %s", req.Scheme, facilitator.scheme),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks for each test run
			mockClient.ExpectedCalls = nil 
			tt.setupMock()

			payloadStr := mustNewEVMPayload(t, fromAddr, tt.payloadNonce, tt.payloadAmount, placeholderSignature)
			
			payload := &types.PaymentPayload{
				Scheme:  types.EVM, // Default, override for specific test
				Network: "base-sepolia",
				Payload: payloadStr,
			}

			currentReq := &types.PaymentRequirements{
				Scheme:  req.Scheme,
				Network: req.Network,
				Asset:   req.Asset,
			}

			if tt.name == "Scheme Mismatch - Payload" {
				payload.Scheme = "other-scheme"
			}


			resp, err := facilitator.Verify(payload, currentReq)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedIsValid, resp.IsValid)
				if !tt.expectedIsValid {
					assert.Equal(t, tt.expectedInvalidReason, resp.InvalidReason)
				}
				if resp.Payer != "" { // Payer should be set if EVM payload parsing succeeds
					assert.Equal(t, fromAddr.String(), resp.Payer)
				}
			}
			mockClient.AssertExpectations(t)
		})
	}
}
