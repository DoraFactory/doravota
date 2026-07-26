package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

const (
	flagNetworkID     = "network-id-base64"
	flagPolicyVersion = "policy-version"
)

type encodedKeyOutput struct {
	Algorithm      string `json:"algorithm"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PublicKey      string `json:"public_key_base64"`
	Proof          string `json:"proof_base64,omitempty"`
	Signature      string `json:"signature_base64,omitempty"`
}

func keygenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen [private-key-output]",
		Short: "Generate an ML-DSA-65 key pair; the private file is created with mode 0600",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			publicKey, privateKey, err := pqccrypto.GenerateMLDSA65Key(nil)
			if err != nil {
				return err
			}
			defer clear(privateKey)
			file, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("create private key file without overwrite: %w", err)
			}
			complete := false
			defer func() {
				if !complete {
					_ = os.Remove(args[0])
				}
			}()
			if _, err := file.Write(privateKey); err != nil {
				_ = file.Close()
				return fmt.Errorf("write private key: %w", err)
			}
			if err := file.Sync(); err != nil {
				_ = file.Close()
				return fmt.Errorf("sync private key: %w", err)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("close private key: %w", err)
			}
			complete = true
			return json.NewEncoder(command.OutOrStdout()).Encode(encodedKeyOutput{
				Algorithm:      "ML-DSA-65",
				PrivateKeyFile: args[0],
				PublicKey:      base64.StdEncoding.EncodeToString(publicKey),
			})
		},
	}
}

func createKeyProofCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "create-key-proof [private-key-file] [owner] [key-id] [role] [purpose]",
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
			privateKey, err := pqcauthclient.LoadPrivateKeyFile(args[0])
			if err != nil {
				return err
			}
			defer clear(privateKey)
			publicKey, err := pqccrypto.MLDSA65PublicKeyFromPrivate(privateKey)
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
			proof, err := pqccrypto.SignMLDSA65(privateKey, signBytes, signatureContext, true)
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
