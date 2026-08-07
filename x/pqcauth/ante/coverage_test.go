package ante

import (
	"errors"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/stretchr/testify/require"

	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type extensionOptionsTxStub struct {
	messages    []sdk.Msg
	critical    []*codectypes.Any
	nonCritical []*codectypes.Any
}

func (tx extensionOptionsTxStub) GetMsgs() []sdk.Msg { return tx.messages }
func (extensionOptionsTxStub) ValidateBasic() error  { return nil }
func (tx extensionOptionsTxStub) GetExtensionOptions() []*codectypes.Any {
	return tx.critical
}
func (tx extensionOptionsTxStub) GetNonCriticalExtensionOptions() []*codectypes.Any {
	return tx.nonCritical
}

type sigVerifiableTxStub struct {
	extensionOptionsTxStub
	signers    []sdk.AccAddress
	signatures []txsigning.SignatureV2
	signErr    error
}

func (tx sigVerifiableTxStub) GetSigners() []sdk.AccAddress { return tx.signers }
func (tx sigVerifiableTxStub) GetPubKeys() ([]cryptotypes.PubKey, error) {
	return make([]cryptotypes.PubKey, len(tx.signers)), nil
}
func (tx sigVerifiableTxStub) GetSignaturesV2() ([]txsigning.SignatureV2, error) {
	return tx.signatures, tx.signErr
}

func encodedExtension(
	t testing.TB,
	extension types.ExtensionPQCAuth,
) *codectypes.Any {
	t.Helper()
	encoded, err := extension.Marshal()
	require.NoError(t, err)
	return &codectypes.Any{
		TypeUrl: types.ExtensionPQCAuthTypeURL,
		Value:   encoded,
	}
}

func validExtensionEntry() types.SignerPQCSignature {
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	if err != nil {
		panic(err)
	}
	return types.SignerPQCSignature{
		Signer:        sdk.AccAddress(make([]byte, 20)).String(),
		SignerIndex:   0,
		KeyId:         1,
		Algorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		PolicyVersion: 1,
		Signature:     make([]byte, signatureSize),
	}
}

func TestExtensionOptionCheckerDelegatesOnlyUnknownOptions(t *testing.T) {
	pqcOption := &codectypes.Any{TypeUrl: types.ExtensionPQCAuthTypeURL}
	otherOption := &codectypes.Any{TypeUrl: "/test.Other"}

	require.True(t, ExtensionOptionChecker(nil)(pqcOption))
	require.False(t, ExtensionOptionChecker(nil)(nil))
	require.False(t, ExtensionOptionChecker(nil)(otherOption))

	var delegated *codectypes.Any
	checker := ExtensionOptionChecker(func(option *codectypes.Any) bool {
		delegated = option
		return true
	})
	require.True(t, checker(otherOption))
	require.Same(t, otherOption, delegated)
}

func TestExtractExtensionStructureMatrix(t *testing.T) {
	params := types.DefaultParams()
	entry := validExtensionEntry()
	valid := types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures:    []types.SignerPQCSignature{entry},
	}
	validAny := encodedExtension(t, valid)

	extension, found, err := ExtractExtension(extensionOptionsTxStub{}, params)
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, extension)

	extension, found, err = ExtractExtension(extensionOptionsTxStub{
		critical: []*codectypes.Any{validAny},
	}, params)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, valid, *extension)

	testCases := []struct {
		name   string
		tx     extensionOptionsTxStub
		params types.Params
	}{
		{
			name: "non-critical",
			tx: extensionOptionsTxStub{
				nonCritical: []*codectypes.Any{validAny},
			},
			params: params,
		},
		{
			name: "not-last",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{
					validAny,
					{TypeUrl: "/test.Other"},
				},
			},
			params: params,
		},
		{
			name: "duplicate",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{validAny, validAny},
			},
			params: params,
		},
		{
			name: "too-large",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{validAny},
			},
			params: func() types.Params {
				limited := params
				limited.MaxPqcAuthBytes = 1
				return limited
			}(),
		},
		{
			name: "cannot-decode",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{{
					TypeUrl: types.ExtensionPQCAuthTypeURL,
					Value:   []byte{0xff},
				}},
			},
			params: params,
		},
		{
			name: "unsupported-format",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1 + 1,
					Signatures:    []types.SignerPQCSignature{entry},
				})},
			},
			params: params,
		},
		{
			name: "too-many-signers",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1,
					Signatures: []types.SignerPQCSignature{
						entry,
						func() types.SignerPQCSignature {
							second := entry
							second.SignerIndex = 1
							return second
						}(),
					},
				})},
			},
			params: func() types.Params {
				limited := params
				limited.MaxPqcSigners = 1
				return limited
			}(),
		},
		{
			name: "unordered-signers",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1,
					Signatures:    []types.SignerPQCSignature{entry, entry},
				})},
			},
			params: params,
		},
		{
			name: "incomplete-entry",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1,
					Signatures: []types.SignerPQCSignature{func() types.SignerPQCSignature {
						incomplete := entry
						incomplete.KeyId = 0
						return incomplete
					}()},
				})},
			},
			params: params,
		},
		{
			name: "unsupported-algorithm",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1,
					Signatures: []types.SignerPQCSignature{func() types.SignerPQCSignature {
						unsupported := entry
						unsupported.Algorithm = types.Algorithm(99)
						return unsupported
					}()},
				})},
			},
			params: params,
		},
		{
			name: "wrong-signature-length",
			tx: extensionOptionsTxStub{
				critical: []*codectypes.Any{encodedExtension(t, types.ExtensionPQCAuth{
					FormatVersion: types.FormatVersionV1,
					Signatures: []types.SignerPQCSignature{func() types.SignerPQCSignature {
						short := entry
						short.Signature = short.Signature[:1]
						return short
					}()},
				})},
			},
			params: params,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := ExtractExtension(testCase.tx, testCase.params)
			require.Error(t, err)
		})
	}
}

func TestExtensionFingerprintIncludesCriticalAndNonCriticalOptions(t *testing.T) {
	noExtensions := extensionOptionsFingerprint(extensionOptionsTxStub{})
	nonExtensionTx := extensionOptionsFingerprint(struct{ sdk.Tx }{})
	require.NotEqual(t, noExtensions, nonExtensionTx)

	withNil := extensionOptionsFingerprint(extensionOptionsTxStub{
		critical: []*codectypes.Any{nil},
	})
	withCritical := extensionOptionsFingerprint(extensionOptionsTxStub{
		critical: []*codectypes.Any{{TypeUrl: "/test.One", Value: []byte{1}}},
	})
	withNonCritical := extensionOptionsFingerprint(extensionOptionsTxStub{
		nonCritical: []*codectypes.Any{{TypeUrl: "/test.One", Value: []byte{1}}},
	})
	require.NotEqual(t, noExtensions, withNil)
	require.NotEqual(t, withNil, withCritical)
	require.NotEqual(t, withCritical, withNonCritical)
}

func TestRequireDirectSignModeMatrix(t *testing.T) {
	require.ErrorIs(t, requireDirectSignMode(extensionOptionsTxStub{}, false), types.ErrUnsupportedSignMode)

	expected := errors.New("signatures unavailable")
	require.ErrorContains(t, requireDirectSignMode(sigVerifiableTxStub{
		signErr: expected,
	}, false), expected.Error())

	require.ErrorIs(t, requireDirectSignMode(sigVerifiableTxStub{
		signatures: []txsigning.SignatureV2{{
			Data: &txsigning.MultiSignatureData{},
		}},
	}, false), types.ErrUnsupportedSignMode)
	require.ErrorIs(t, requireDirectSignMode(sigVerifiableTxStub{
		signatures: []txsigning.SignatureV2{{
			Data: &txsigning.SingleSignatureData{
				SignMode: txsigning.SignMode_SIGN_MODE_LEGACY_AMINO_JSON,
			},
		}},
	}, false), types.ErrUnsupportedSignMode)
	require.NoError(t, requireDirectSignMode(sigVerifiableTxStub{
		signatures: []txsigning.SignatureV2{{
			Data: &txsigning.SingleSignatureData{
				SignMode: txsigning.SignMode_SIGN_MODE_DIRECT,
			},
		}},
	}, false))

	unsignedSimulation := sigVerifiableTxStub{
		signatures: []txsigning.SignatureV2{{
			Data: &txsigning.SingleSignatureData{
				SignMode: txsigning.SignMode_SIGN_MODE_UNSPECIFIED,
			},
		}},
	}
	require.NoError(t, requireDirectSignMode(unsignedSimulation, true))
	require.ErrorIs(t, requireDirectSignMode(unsignedSimulation, false), types.ErrUnsupportedSignMode)
	require.ErrorIs(t, requireDirectSignMode(sigVerifiableTxStub{
		signatures: []txsigning.SignatureV2{{
			Data: &txsigning.SingleSignatureData{
				SignMode:  txsigning.SignMode_SIGN_MODE_UNSPECIFIED,
				Signature: []byte{1},
			},
		}},
	}, true), types.ErrUnsupportedSignMode)
}

func TestPQCStateContextUsesLatestCommittedHeightOnlyForSimulation(t *testing.T) {
	ctx, _, _, _, _ := setupAnteTest(t)
	commitStore, ok := ctx.MultiStore().(storetypes.CommitMultiStore)
	require.True(t, ok)
	commitID := commitStore.Commit()
	require.Positive(t, commitID.Version)

	heightZero := ctx.WithBlockHeight(0)
	require.Equal(t, int64(0), pqcStateContext(heightZero, false).BlockHeight())
	require.Equal(t, commitID.Version, pqcStateContext(heightZero, true).BlockHeight())
	require.Equal(t, int64(10), pqcStateContext(ctx, true).BlockHeight())
}

func TestPQCRequirementDecisionMatrix(t *testing.T) {
	require.False(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_DISABLED,
		types.AccountPolicy{},
		false,
	))
	require.False(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_OPTIONAL,
		types.AccountPolicy{},
		true,
	))
	require.False(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED,
		types.AccountPolicy{},
		false,
	))
	require.True(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED_FOR_REGISTERED,
		types.AccountPolicy{},
		true,
	))
	require.True(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_REQUIRED,
		types.AccountPolicy{},
		false,
	))
	require.True(t, pqcRequired(
		types.EnforcementMode(99),
		types.AccountPolicy{},
		false,
	))
	require.True(t, pqcRequired(
		types.EnforcementMode_ENFORCEMENT_MODE_DISABLED,
		types.AccountPolicy{SelfEnforced: true},
		true,
	))
}

func TestLifecycleMessageClassification(t *testing.T) {
	signer := sdk.AccAddress(make([]byte, 20))
	owner := signer.String()
	for _, message := range []sdk.Msg{
		&types.MsgRotateKey{Owner: owner},
		&types.MsgRotateRecoveryKey{Owner: owner},
		&types.MsgSetProtection{Owner: owner},
		&types.MsgRevokeKey{Owner: owner},
	} {
		require.True(t, lifecycleRequiresActivePQC(
			extensionOptionsTxStub{messages: []sdk.Msg{message}},
			signer,
		))
	}
	require.False(t, lifecycleRequiresActivePQC(
		extensionOptionsTxStub{messages: []sdk.Msg{&types.MsgRegisterKey{Owner: owner}}},
		signer,
	))
	require.False(t, lifecycleRequiresActivePQC(
		extensionOptionsTxStub{messages: []sdk.Msg{
			&types.MsgSetProtection{Owner: owner},
			&types.MsgSetProtection{Owner: owner},
		}},
		signer,
	))
	require.False(t, lifecycleRequiresActivePQC(
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgSetProtection{
				Owner: sdk.AccAddress(make([]byte, 21)).String(),
			}},
		},
		signer,
	))
}

func TestLifecycleProofSubstitutionMatrix(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)
	activeSigner := accountKeeper.account.GetAddress()
	unregisteredSigner := sdk.AccAddress(make([]byte, 20))

	require.True(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRegisterKey{Owner: unregisteredSigner.String()}},
		},
		unregisteredSigner,
		false,
	))
	require.False(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRegisterKey{Owner: activeSigner.String()}},
		},
		activeSigner,
		true,
	))

	policy, found := moduleKeeper.GetEffectiveAccountPolicy(ctx, activeSigner)
	require.True(t, found)
	policy.RecoveryKeyId = 2
	require.NoError(t, moduleKeeper.SetAccountPolicy(ctx, activeSigner, policy))
	require.True(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRecoverKey{
				Owner:         activeSigner.String(),
				RecoveryKeyId: 2,
			}},
		},
		activeSigner,
		true,
	))
	require.False(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgRecoverKey{
				Owner:         activeSigner.String(),
				RecoveryKeyId: 3,
			}},
		},
		activeSigner,
		true,
	))
	require.False(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{&types.MsgSetProtection{Owner: activeSigner.String()}},
		},
		activeSigner,
		true,
	))
	require.False(t, decorator.lifecycleProofSubstitutesPQC(
		ctx,
		extensionOptionsTxStub{
			messages: []sdk.Msg{
				&types.MsgRecoverKey{Owner: activeSigner.String(), RecoveryKeyId: 2},
				&types.MsgRecoverKey{Owner: activeSigner.String(), RecoveryKeyId: 2},
			},
		},
		activeSigner,
		true,
	))
}

func TestValidateLifecycleRegistrationMatrix(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)
	params := moduleKeeper.GetParams(ctx)
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	recoveryPublicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	unregistered := sdk.AccAddress(make([]byte, 20)).String()
	register := &types.MsgRegisterKey{
		Owner:                unregistered,
		ExpectedSigningKeyId: 1,
		SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		SigningPublicKey:     publicKey,
		SigningKeyProof:      make([]byte, signatureSize),
		RecoveryAlgorithm:    types.Algorithm_ALGORITHM_ML_DSA_65,
		RecoveryPublicKey:    recoveryPublicKey,
		RecoveryKeyProof:     make([]byte, signatureSize),
		SelfEnforce:          true,
	}

	gasMeter := newRecordingGasMeter()
	err = decorator.validateLifecycleProofs(
		ctx.WithGasMeter(gasMeter),
		extensionOptionsTxStub{messages: []sdk.Msg{register}},
		params,
		true,
	)
	require.NoError(t, err)
	require.Len(t, gasMeter.chargesFor("simulated pqcauth key proof verification"), 2)

	err = decorator.validateLifecycleProofs(
		ctx.WithGasMeter(sdk.NewInfiniteGasMeter()),
		extensionOptionsTxStub{messages: []sdk.Msg{register}},
		params,
		false,
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)

	alreadyRegistered := *register
	alreadyRegistered.Owner = accountKeeper.account.GetAddress().String()
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{&alreadyRegistered}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrAlreadyRegistered)

	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{register, register}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)

	invalid := *register
	invalid.ExpectedSigningKeyId = 0
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{&invalid}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrUnexpectedKeyID)

	closed := params
	closed.RegistrationCutoffHeight = uint64(ctx.BlockHeight())
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{register}},
		closed,
		true,
	)
	require.ErrorIs(t, err, types.ErrRegistrationClosed)

	unexpectedID := *register
	unexpectedID.ExpectedSigningKeyId = 2
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{&unexpectedID}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrUnexpectedKeyID)
}

func TestValidateLifecycleStateFailureMatrix(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	decorator := NewVerifyPQCDecorator(moduleKeeper, accountKeeper)
	params := moduleKeeper.GetParams(ctx)
	publicKey, _, err := pqccrypto.GenerateMLDSA65Key(nil)
	require.NoError(t, err)
	_, signatureSize, err := pqccrypto.Sizes(pqccrypto.AlgorithmMLDSA65)
	require.NoError(t, err)
	activeOwner := accountKeeper.account.GetAddress().String()
	unregisteredOwner := sdk.AccAddress(make([]byte, 20)).String()

	rotate := func(owner string) *types.MsgRotateKey {
		return &types.MsgRotateKey{
			Owner:            owner,
			ExpectedNewKeyId: 2,
			NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
			NewPublicKey:     publicKey,
			NewKeyProof:      make([]byte, signatureSize),
		}
	}
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{rotate(unregisteredOwner)}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrPolicyNotFound)

	policy, found := moduleKeeper.GetEffectiveAccountPolicy(
		ctx,
		accountKeeper.account.GetAddress(),
	)
	require.True(t, found)
	policy.PendingSigningKeyId = 2
	policy.PendingEffectiveHeight = uint64(ctx.BlockHeight() + 1)
	policy.PendingPolicyVersion = policy.PolicyVersion + 1
	require.NoError(t, moduleKeeper.SetAccountPolicy(
		ctx,
		accountKeeper.account.GetAddress(),
		policy,
	))
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{rotate(activeOwner)}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrPendingChange)

	policy.PendingSigningKeyId = 0
	policy.PendingEffectiveHeight = 0
	policy.PendingPolicyVersion = 0
	require.NoError(t, moduleKeeper.SetAccountPolicy(
		ctx,
		accountKeeper.account.GetAddress(),
		policy,
	))

	rotateRecovery := &types.MsgRotateRecoveryKey{
		Owner:            unregisteredOwner,
		ExpectedNewKeyId: 1,
		NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewPublicKey:     publicKey,
		NewKeyProof:      make([]byte, signatureSize),
	}
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{rotateRecovery}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrPolicyNotFound)

	recover := &types.MsgRecoverKey{
		Owner:                   activeOwner,
		RecoveryKeyId:           2,
		RecoverySignature:       make([]byte, signatureSize),
		ExpectedNewSigningKeyId: 3,
		NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
		NewSigningPublicKey:     publicKey,
		NewSigningKeyProof:      make([]byte, signatureSize),
	}
	err = decorator.validateLifecycleProofs(
		ctx,
		extensionOptionsTxStub{messages: []sdk.Msg{recover}},
		params,
		true,
	)
	require.ErrorIs(t, err, types.ErrInvalidKeyProof)

	for _, message := range []sdk.Msg{
		&types.MsgSetProtection{Owner: activeOwner},
		&types.MsgRevokeKey{Owner: activeOwner, KeyId: 1},
	} {
		err = decorator.validateLifecycleProofs(
			ctx,
			extensionOptionsTxStub{messages: []sdk.Msg{message, message}},
			params,
			true,
		)
		require.ErrorIs(t, err, types.ErrInvalidKeyProof)
	}
}

func TestLifecycleHelpersCoverFailClosedModes(t *testing.T) {
	ctx, moduleKeeper, accountKeeper, _, _ := setupAnteTest(t)
	params := moduleKeeper.GetParams(ctx)

	require.Equal(
		t,
		"pqcauth key proof verification",
		lifecycleProofGasDescriptor(false, "key proof"),
	)
	require.Nil(t, topLevelLifecycleMessage(extensionOptionsTxStub{}))
	require.Nil(t, topLevelLifecycleMessage(extensionOptionsTxStub{
		messages: []sdk.Msg{&types.MsgUpdateParams{}},
	}))
	require.Nil(t, topLevelLifecycleMessage(extensionOptionsTxStub{
		messages: []sdk.Msg{
			&types.MsgSetProtection{},
			&types.MsgSetProtection{},
		},
	}))

	require.NoError(t, keyChangeAllowed(ctx, params, false))
	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_NEW_KEYS
	require.ErrorIs(t, keyChangeAllowed(ctx, params, false), types.ErrEmergencyPause)
	params.EmergencyMode = types.EmergencyMode_EMERGENCY_MODE_PAUSE_PQC_TRANSACTIONS
	require.ErrorIs(t, keyChangeAllowed(ctx, params, false), types.ErrEmergencyPause)

	params = moduleKeeper.GetParams(ctx)
	params.AllowedAlgorithms = []types.Algorithm{
		types.Algorithm_ALGORITHM_ML_DSA_65,
	}
	err := verifyLifecycleKeyProof(
		ctx,
		params,
		true,
		accountKeeper.account.GetAddress().String(),
		2,
		types.Algorithm(99),
		nil,
		types.KeyRole_KEY_ROLE_SIGNING,
		types.PurposeRotateSigning,
		1,
		nil,
		[]byte(types.RotateProofContext),
	)
	require.ErrorIs(t, err, types.ErrUnsupportedAlgorithm)
}

func FuzzExtractExtensionDoesNotPanic(f *testing.F) {
	valid := types.ExtensionPQCAuth{
		FormatVersion: types.FormatVersionV1,
		Signatures:    []types.SignerPQCSignature{validExtensionEntry()},
	}
	encoded, err := valid.Marshal()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(encoded)
	f.Add([]byte{0xff})
	f.Add([]byte{})
	params := types.DefaultParams()

	f.Fuzz(func(t *testing.T, value []byte) {
		_, _, _ = ExtractExtension(extensionOptionsTxStub{
			critical: []*codectypes.Any{{
				TypeUrl: types.ExtensionPQCAuthTypeURL,
				Value:   value,
			}},
		}, params)
	})
}
