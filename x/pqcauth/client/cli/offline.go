package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	flagNetworkID     = "network-id-base64"
	flagPolicyVersion = "policy-version"
)

type encodedKeyOutput struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key_base64"`
	Proof     string `json:"proof_base64,omitempty"`
	Signature string `json:"signature_base64,omitempty"`
}

func createKeyProofCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "create-key-proof [key-name] [owner] [key-id] [role] [purpose]",
		Short: "Create an offline registration, rotation, or recovery key proof",
		Args:  cobra.ExactArgs(5),
		RunE: func(command *cobra.Command, args []string) error {
			keyID, err := strconv.ParseUint(args[2], 10, 64)
			if err != nil || keyID == 0 {
				return fmt.Errorf("key id must be a positive integer")
			}
			role, err := parseKeyRole(args[3])
			if err != nil {
				return err
			}
			signatureContext, err := proofContext(args[4], role)
			if err != nil {
				return err
			}
			networkIDEncoded, _ := command.Flags().GetString(flagNetworkID)
			networkID, err := decodeBase64("network id", networkIDEncoded)
			if err != nil {
				return err
			}
			chainID, _ := command.Flags().GetString(flags.FlagChainID)
			if chainID == "" {
				return fmt.Errorf("--%s is required", flags.FlagChainID)
			}
			policyVersion, _ := command.Flags().GetUint64(flagPolicyVersion)
			signer, cleanup, err := offlineSigner(command, args[0])
			if err != nil {
				return err
			}
			defer cleanup()
			publicKey, err := signer.PublicKey(command.Context())
			if err != nil {
				return err
			}
			signBytes, err := types.MarshalKeyProofDocV1(types.KeyProofDocV1{
				FormatVersion:        types.FormatVersionV1,
				NetworkId:            networkID,
				ChainId:              chainID,
				Owner:                args[1],
				ProposedKeyId:        keyID,
				Algorithm:            types.Algorithm_ALGORITHM_ML_DSA_65,
				PublicKey:            publicKey,
				Role:                 role,
				Purpose:              args[4],
				CurrentPolicyVersion: policyVersion,
			})
			if err != nil {
				return err
			}
			proof, err := signer.Sign(command.Context(), signBytes, signatureContext)
			if err != nil {
				return err
			}
			return json.NewEncoder(command.OutOrStdout()).Encode(encodedKeyOutput{
				Algorithm: "ML-DSA-65",
				PublicKey: base64.StdEncoding.EncodeToString(publicKey),
				Proof:     base64.StdEncoding.EncodeToString(proof),
			})
		},
	}
	command.Flags().String(flagNetworkID, "", "base64 network_id from `query pqcauth params`")
	command.Flags().Uint64(flagPolicyVersion, 0, "current account policy version")
	command.Flags().String(flags.FlagChainID, "", "chain ID")
	addOfflineKeyFlags(command)
	_ = command.MarkFlagRequired(flagNetworkID)
	return command
}

func parseKeyRole(value string) (types.KeyRole, error) {
	switch value {
	case "signing":
		return types.KeyRole_KEY_ROLE_SIGNING, nil
	case "recovery":
		return types.KeyRole_KEY_ROLE_RECOVERY, nil
	default:
		return types.KeyRole_KEY_ROLE_UNSPECIFIED, fmt.Errorf("role must be signing or recovery")
	}
}

func proofContext(purpose string, role types.KeyRole) ([]byte, error) {
	switch purpose {
	case types.PurposeRegisterSigning:
		if role != types.KeyRole_KEY_ROLE_SIGNING {
			return nil, fmt.Errorf("register-signing requires signing role")
		}
		return []byte(types.RegisterProofContext), nil
	case types.PurposeRegisterRecovery:
		if role != types.KeyRole_KEY_ROLE_RECOVERY {
			return nil, fmt.Errorf("register-recovery requires recovery role")
		}
		return []byte(types.RegisterProofContext), nil
	case types.PurposeRotateSigning:
		if role != types.KeyRole_KEY_ROLE_SIGNING {
			return nil, fmt.Errorf("rotate-signing requires signing role")
		}
		return []byte(types.RotateProofContext), nil
	case types.PurposeRotateRecovery:
		if role != types.KeyRole_KEY_ROLE_RECOVERY {
			return nil, fmt.Errorf("rotate-recovery requires recovery role")
		}
		return []byte(types.RotateRecoveryContext), nil
	case types.PurposeRecoverSigning:
		if role != types.KeyRole_KEY_ROLE_SIGNING {
			return nil, fmt.Errorf("recover-signing requires signing role")
		}
		return []byte(types.RecoveryKeyProofContext), nil
	default:
		return nil, fmt.Errorf("unsupported purpose %q", purpose)
	}
}
