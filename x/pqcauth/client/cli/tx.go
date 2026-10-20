package cli

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	flagPQCPrivateKey        = "pqc-private-key-file"
	flagPQCSignBundleOutput  = "pqc-sign-bundle-output"
	flagSelfEnforce          = "self-enforce"
	flagRecoveryPublicKey    = "recovery-public-key-base64"
	flagRecoveryProof        = "recovery-proof-base64"
	flagRecoveryPrivateKey   = "recovery-private-key-file"
	flagRecoveryBundleOutput = "recovery-sign-bundle-output"
)

func GetTxCmd() *cobra.Command {
	command := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "Manage post-quantum account authorization",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	command.AddCommand(
		keygenCommand(),
		createKeyProofCommand(),
		prepareBundleCommand(),
		signBundleCommand(),
		broadcastBundleCommand(),
		signRecoveryBundleCommand(),
		broadcastRecoveryBundleCommand(),
		registerKeyCommand(),
		rotateKeyCommand(),
		rotateRecoveryKeyCommand(),
		setProtectionCommand(),
		revokeKeyCommand(),
		recoverKeyCommand(),
		cancelRecoveryCommand(),
	)
	return command
}

func registerKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "register-key [expected-key-id] [public-key-base64] [proof-base64]",
		Short: "Register distinct ML-DSA-65 signing and recovery keys at H+1",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			keyID, publicKey, proof, err := parseKeyMaterial(args)
			if err != nil {
				return err
			}
			selfEnforce, _ := command.Flags().GetBool(flagSelfEnforce)
			recoveryPublicKeyEncoded, _ := command.Flags().GetString(flagRecoveryPublicKey)
			recoveryProofEncoded, _ := command.Flags().GetString(flagRecoveryProof)
			if recoveryPublicKeyEncoded == "" || recoveryProofEncoded == "" {
				return fmt.Errorf("recovery public key and proof are required")
			}
			recoveryPublicKey, err := decodeBase64("recovery public key", recoveryPublicKeyEncoded)
			if err != nil {
				return err
			}
			recoveryProof, err := decodeBase64("recovery proof", recoveryProofEncoded)
			if err != nil {
				return err
			}
			message := &types.MsgRegisterKey{
				Owner:                clientCtx.GetFromAddress().String(),
				ExpectedSigningKeyId: keyID,
				SigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
				SigningPublicKey:     publicKey,
				SigningKeyProof:      proof,
				SelfEnforce:          selfEnforce,
				RecoveryAlgorithm:    types.Algorithm_ALGORITHM_ML_DSA_65,
				RecoveryPublicKey:    recoveryPublicKey,
				RecoveryKeyProof:     recoveryProof,
			}
			return sdktx.GenerateOrBroadcastTxCLI(clientCtx, command.Flags(), message)
		},
	}
	command.Flags().Bool(flagSelfEnforce, true, "require PQC authorization after activation")
	command.Flags().String(flagRecoveryPublicKey, "", "required ML-DSA-65 recovery public key in base64")
	command.Flags().String(flagRecoveryProof, "", "required recovery key proof in base64; binds expected-key-id+1")
	flags.AddTxFlagsToCmd(command)
	return command
}

func rotateKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "rotate-key [expected-new-key-id] [new-public-key-base64] [new-proof-base64]",
		Short: "Rotate the active ML-DSA-65 signing key at H+1",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			keyID, publicKey, proof, err := parseKeyMaterial(args)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagPQCPrivateKey)
			return generateOrBroadcastProtectedTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgRotateKey{
					Owner:            clientCtx.GetFromAddress().String(),
					ExpectedNewKeyId: keyID,
					NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
					NewPublicKey:     publicKey,
					NewKeyProof:      proof,
				},
			)
		},
	}
	addProtectedTxFlags(command)
	return command
}

func rotateRecoveryKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "rotate-recovery-key [expected-new-key-id] [new-public-key-base64] [new-proof-base64]",
		Short: "Rotate the offline ML-DSA-65 recovery key at H+1",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			keyID, publicKey, proof, err := parseKeyMaterial(args)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagPQCPrivateKey)
			return generateOrBroadcastProtectedTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgRotateRecoveryKey{
					Owner:            clientCtx.GetFromAddress().String(),
					ExpectedNewKeyId: keyID,
					NewAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
					NewPublicKey:     publicKey,
					NewKeyProof:      proof,
				},
			)
		},
	}
	addProtectedTxFlags(command)
	return command
}

func setProtectionCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "set-protection [true|false]",
		Short: "Schedule per-account PQC enforcement at H+1",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			enabled, err := strconv.ParseBool(args[0])
			if err != nil {
				return fmt.Errorf("enabled must be true or false")
			}
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagPQCPrivateKey)
			return generateOrBroadcastProtectedTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgSetProtection{
					Owner:   clientCtx.GetFromAddress().String(),
					Enabled: enabled,
				},
			)
		},
	}
	addProtectedTxFlags(command)
	return command
}

func revokeKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "revoke-key [key-id]",
		Short: "Revoke a historical, non-active PQC key",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			keyID, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil || keyID == 0 {
				return fmt.Errorf("key id must be a positive integer")
			}
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagPQCPrivateKey)
			return generateOrBroadcastProtectedTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgRevokeKey{Owner: clientCtx.GetFromAddress().String(), KeyId: keyID},
			)
		},
	}
	addProtectedTxFlags(command)
	return command
}

func recoverKeyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "recover-key [recovery-key-id] [expected-new-key-id] [new-public-key-base64] [new-proof-base64]",
		Short: "Recover the signing key using transaction-bound offline recovery authorization",
		Args:  cobra.ExactArgs(4),
		RunE: func(command *cobra.Command, args []string) error {
			recoveryKeyID, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil || recoveryKeyID == 0 {
				return fmt.Errorf("recovery key id must be a positive integer")
			}
			newKeyID, publicKey, proof, err := parseKeyMaterial(args[1:])
			if err != nil {
				return err
			}
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagRecoveryPrivateKey)
			return generateOrBroadcastRecoveryTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgRecoverKey{
					Owner:                   clientCtx.GetFromAddress().String(),
					RecoveryKeyId:           recoveryKeyID,
					ExpectedNewSigningKeyId: newKeyID,
					NewSigningAlgorithm:     types.Algorithm_ALGORITHM_ML_DSA_65,
					NewSigningPublicKey:     publicKey,
					NewSigningKeyProof:      proof,
				},
			)
		},
	}
	command.Flags().String(
		flagRecoveryPrivateKey,
		"",
		"path to the offline recovery ML-DSA-65 private key (mode 0600)",
	)
	command.Flags().String(
		flagRecoveryBundleOutput,
		"",
		"write a transaction-bound recovery sign bundle for offline signing",
	)
	flags.AddTxFlagsToCmd(command)
	return command
}

func cancelRecoveryCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "cancel-recovery [pending-signing-key-id] [pending-policy-version]",
		Short: "Cancel a delayed recovery with the current PQC signing key",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			pendingKeyID, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil || pendingKeyID == 0 {
				return fmt.Errorf("pending signing key id must be a positive integer")
			}
			pendingPolicyVersion, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil || pendingPolicyVersion == 0 {
				return fmt.Errorf("pending policy version must be a positive integer")
			}
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			privateKeyPath, _ := command.Flags().GetString(flagPQCPrivateKey)
			return generateOrBroadcastProtectedTx(
				command.Context(),
				clientCtx,
				command.Flags(),
				privateKeyPath,
				&types.MsgCancelRecovery{
					Owner:                        clientCtx.GetFromAddress().String(),
					ExpectedPendingSigningKeyId:  pendingKeyID,
					ExpectedPendingPolicyVersion: pendingPolicyVersion,
				},
			)
		},
	}
	addProtectedTxFlags(command)
	return command
}

func addProtectedTxFlags(command *cobra.Command) {
	command.Flags().String(flagPQCPrivateKey, "", "path to the active encoded ML-DSA-65 private key (mode 0600)")
	command.Flags().String(
		flagPQCSignBundleOutput,
		"",
		"write an unsigned PQC sign bundle for offline signing instead of signing and broadcasting",
	)
	flags.AddTxFlagsToCmd(command)
}

func parseKeyMaterial(args []string) (uint64, []byte, []byte, error) {
	keyID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || keyID == 0 {
		return 0, nil, nil, fmt.Errorf("key id must be a positive integer")
	}
	publicKey, err := decodeBase64("public key", args[1])
	if err != nil {
		return 0, nil, nil, err
	}
	proof, err := decodeBase64("proof", args[2])
	if err != nil {
		return 0, nil, nil, err
	}
	return keyID, publicKey, proof, nil
}

func decodeBase64(label, value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s as base64: %w", label, err)
	}
	return decoded, nil
}
