package keeper

import (
	"bytes"
	"context"
	"testing"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

// Direct module dispatch must remain fail-closed even if an indirect execution
// path is added in the future and is not yet known to the Ante container filter.
func TestAllLifecycleServersRejectMissingOrDifferentAnteAuthorization(t *testing.T) {
	k, ctx := setupKeeper(t, 10)
	require.NoError(t, k.SetParams(ctx, types.DefaultParams()))
	server := NewMsgServer(k)
	owner := sdk.AccAddress(bytes.Repeat([]byte{0x55}, 20)).String()
	pub, _ := keyPair(1)
	recoveryPub, _ := keyPair(2)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	proof := make([]byte, signatureSize)
	algorithm := types.Algorithm_ALGORITHM_ML_DSA_65
	messages := []sdk.Msg{
		&types.MsgRegisterKey{Owner: owner, ExpectedSigningKeyId: 1, SigningAlgorithm: algorithm, SigningPublicKey: pub, SigningKeyProof: proof, RecoveryAlgorithm: algorithm, RecoveryPublicKey: recoveryPub, RecoveryKeyProof: proof, SelfEnforce: true},
		&types.MsgRotateKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: algorithm, NewPublicKey: pub, NewKeyProof: proof},
		&types.MsgRotateRecoveryKey{Owner: owner, ExpectedNewKeyId: 3, NewAlgorithm: algorithm, NewPublicKey: pub, NewKeyProof: proof},
		&types.MsgSetProtection{Owner: owner, Enabled: false},
		&types.MsgRevokeKey{Owner: owner, KeyId: 1},
		&types.MsgRecoverKey{Owner: owner, RecoveryKeyId: 2, ExpectedNewSigningKeyId: 3, ExpectedRecoveryDelayBlocks: types.DefaultRecoveryDelayBlocks, NewSigningAlgorithm: algorithm, NewSigningPublicKey: pub, NewSigningKeyProof: proof, RecoverySignature: proof},
		&types.MsgCancelRecovery{Owner: owner, ExpectedPendingSigningKeyId: 3, ExpectedPendingPolicyVersion: 2},
	}
	call := func(ctx context.Context, msg sdk.Msg) error {
		var err error
		switch msg := msg.(type) {
		case *types.MsgRegisterKey:
			_, err = server.RegisterKey(ctx, msg)
		case *types.MsgRotateKey:
			_, err = server.RotateKey(ctx, msg)
		case *types.MsgRotateRecoveryKey:
			_, err = server.RotateRecoveryKey(ctx, msg)
		case *types.MsgSetProtection:
			_, err = server.SetProtection(ctx, msg)
		case *types.MsgRevokeKey:
			_, err = server.RevokeKey(ctx, msg)
		case *types.MsgRecoverKey:
			_, err = server.RecoverKey(ctx, msg)
		case *types.MsgCancelRecovery:
			_, err = server.CancelRecovery(ctx, msg)
		default:
			t.Fatalf("unhandled lifecycle message %T", msg)
		}
		return err
	}
	for _, msg := range messages {
		t.Run(sdk.MsgTypeURL(msg), func(t *testing.T) {
			require.NoError(t, msg.(interface{ ValidateBasic() error }).ValidateBasic())
			require.ErrorIs(t, call(sdk.WrapSDKContext(ctx), msg), types.ErrNestedLifecycle)
			wrong := authorizedLifecycleContext(t, ctx, &types.MsgSetProtection{Owner: owner, Enabled: true})
			require.ErrorIs(t, call(sdk.WrapSDKContext(wrong), msg), types.ErrNestedLifecycle)
		})
	}
	report := k.AuditState(ctx, 20)
	require.True(t, report.Consistent, "%+v", report.Issues)
}
