package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/input"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
	pqccrypto "github.com/DoraFactory/doravota/x/pqcauth/crypto"
	"github.com/DoraFactory/doravota/x/pqcauth/types"
)

type recoveryBundleCommandResult struct {
	Status               string `json:"status"`
	File                 string `json:"file"`
	ChainID              string `json:"chain_id"`
	NetworkID            string `json:"network_id_base64"`
	Owner                string `json:"owner"`
	AccountNumber        uint64 `json:"account_number"`
	Sequence             uint64 `json:"sequence"`
	RecoveryKeyID        uint64 `json:"recovery_key_id"`
	ProposedSigningKeyID uint64 `json:"proposed_signing_key_id"`
	RecoveryAlgorithm    string `json:"recovery_algorithm"`
	ProposedAlgorithm    string `json:"proposed_algorithm"`
	PolicyVersion        uint64 `json:"policy_version"`
	TxSHA256             string `json:"tx_sha256"`
	SignDocSHA256        string `json:"sign_doc_sha256"`
	Signed               bool   `json:"signed"`
}

func generateOrBroadcastRecoveryTx(
	ctx context.Context,
	clientCtx client.Context,
	flagSet *pflag.FlagSet,
	privateKeyPath string,
	message *types.MsgRecoverKey,
) error {
	bundleOutput, _ := flagSet.GetString(flagRecoveryBundleOutput)
	if clientCtx.GenerateOnly {
		return errors.New(
			"use --recovery-sign-bundle-output to prepare a transaction-bound recovery authorization",
		)
	}
	if err := validateRecoverySigningOptions(
		clientCtx.Simulate,
		privateKeyPath,
		bundleOutput,
	); err != nil {
		return err
	}
	algorithm, err := types.CryptoAlgorithm(types.Algorithm_ALGORITHM_ML_DSA_65)
	if err != nil {
		return err
	}
	_, signatureSize, err := pqccrypto.Sizes(algorithm)
	if err != nil {
		return err
	}
	message.RecoverySignature = make([]byte, signatureSize)
	if err := message.ValidateBasic(); err != nil {
		return err
	}

	txf, err := sdktx.NewFactoryCLI(clientCtx, flagSet)
	if err != nil {
		return err
	}
	txf, err = txf.Prepare(clientCtx)
	if err != nil {
		return err
	}
	if txf.SimulateAndExecute() || clientCtx.Simulate {
		if clientCtx.Offline {
			return errors.New("cannot estimate recovery gas in offline mode")
		}
		_, adjusted, err := sdktx.CalculateGas(clientCtx, txf, message)
		if err != nil {
			return err
		}
		txf = txf.WithGas(adjusted)
		_, _ = fmt.Fprintf(os.Stderr, "gas estimate: %d\n", adjusted)
	}
	if clientCtx.Simulate {
		return nil
	}

	builder, err := txf.BuildUnsignedTx(message)
	if err != nil {
		return err
	}
	bundle, summary, err := pqcauthclient.PrepareRecoverySignBundle(
		ctx,
		clientCtx,
		txf,
		builder,
	)
	if err != nil {
		return err
	}
	if bundleOutput != "" {
		encoded, err := pqcauthclient.MarshalRecoverySignBundle(
			clientCtx.TxConfig,
			bundle,
			false,
		)
		if err != nil {
			return err
		}
		if err := writeNewFileAtomic(bundleOutput, encoded, 0o600); err != nil {
			return err
		}
		output := clientCtx.Output
		if output == nil {
			output = os.Stdout
		}
		return printRecoveryBundleResult(output, "prepared", bundleOutput, summary)
	}

	privateKey, err := pqcauthclient.LoadPrivateKeyFile(privateKeyPath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	signedBundle, _, err := pqcauthclient.SignRecoverySignBundleWithPrivateKey(
		ctx,
		clientCtx.TxConfig,
		bundle,
		privateKey,
	)
	if err != nil {
		return err
	}
	builder, _, err = pqcauthclient.AttachRecoverySignBundle(
		ctx,
		clientCtx,
		txf,
		signedBundle,
	)
	if err != nil {
		return err
	}
	if !clientCtx.SkipConfirm {
		txBytes, err := clientCtx.TxConfig.TxJSONEncoder()(builder.GetTx())
		if err != nil {
			return err
		}
		if err := clientCtx.PrintRaw(json.RawMessage(txBytes)); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, string(txBytes))
		}
		ok, err := input.GetConfirmation(
			"confirm transaction-bound recovery before classical signing and broadcast",
			bufio.NewReader(os.Stdin),
			os.Stderr,
		)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("recovery transaction broadcast cancelled")
		}
	}
	if err := sdktx.Sign(txf, clientCtx.GetFromName(), builder, true); err != nil {
		return err
	}
	txBytes, err := clientCtx.TxConfig.TxEncoder()(builder.GetTx())
	if err != nil {
		return err
	}
	response, err := clientCtx.BroadcastTx(txBytes)
	if err != nil {
		return err
	}
	return clientCtx.PrintProto(response)
}

func signRecoveryBundleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "sign-recovery-bundle [prepared-bundle] [recovery-private-key-file] [signed-bundle-output]",
		Short: "Validate and sign a transaction-bound recovery bundle offline",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(command)
			encoded, err := readRegularFile(
				args[0],
				pqcauthclient.MaxRecoverySignBundleBytes,
				"recovery sign bundle",
			)
			if err != nil {
				return err
			}
			bundle, summary, err := pqcauthclient.UnmarshalRecoverySignBundle(
				clientCtx.TxConfig,
				encoded,
				false,
			)
			if err != nil {
				return err
			}
			skipConfirm, _ := command.Flags().GetBool(flags.FlagSkipConfirmation)
			if !skipConfirm {
				decodedTx, err := clientCtx.TxConfig.TxDecoder()(bundle.UnsignedTx)
				if err != nil {
					return fmt.Errorf("decode recovery transaction for review: %w", err)
				}
				transactionJSON, err := clientCtx.TxConfig.TxJSONEncoder()(decodedTx)
				if err != nil {
					return fmt.Errorf("encode recovery transaction for review: %w", err)
				}
				printRecoveryBundleReview(command.ErrOrStderr(), summary, transactionJSON)
				ok, err := input.GetConfirmation(
					"confirm exact recovery transaction hashes before offline ML-DSA signing",
					bufio.NewReader(command.InOrStdin()),
					command.ErrOrStderr(),
				)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("offline recovery signing cancelled")
				}
			}
			privateKey, err := pqcauthclient.LoadPrivateKeyFile(args[1])
			if err != nil {
				return err
			}
			defer clear(privateKey)
			signed, signedSummary, err := pqcauthclient.SignRecoverySignBundleWithPrivateKey(
				command.Context(),
				clientCtx.TxConfig,
				bundle,
				privateKey,
			)
			if err != nil {
				return err
			}
			signedBytes, err := pqcauthclient.MarshalRecoverySignBundle(
				clientCtx.TxConfig,
				signed,
				true,
			)
			if err != nil {
				return err
			}
			if err := writeNewFileAtomic(args[2], signedBytes, 0o600); err != nil {
				return err
			}
			return printRecoveryBundleResult(
				command.OutOrStdout(),
				"signed",
				args[2],
				signedSummary,
			)
		},
	}
	command.Flags().BoolP(
		flags.FlagSkipConfirmation,
		"y",
		false,
		"skip offline recovery signing confirmation",
	)
	return command
}

func broadcastRecoveryBundleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "broadcast-recovery-bundle [signed-bundle]",
		Short: "Revalidate, attach, classically sign, and broadcast a recovery bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			if clientCtx.Offline || clientCtx.GenerateOnly || clientCtx.Simulate {
				return errors.New(
					"broadcast-recovery-bundle requires an online, non-simulation client",
				)
			}
			if err := rejectBundledTxMutationFlags(command.Flags()); err != nil {
				return err
			}
			encoded, err := readRegularFile(
				args[0],
				pqcauthclient.MaxRecoverySignBundleBytes,
				"recovery sign bundle",
			)
			if err != nil {
				return err
			}
			bundle, _, err := pqcauthclient.UnmarshalRecoverySignBundle(
				clientCtx.TxConfig,
				encoded,
				true,
			)
			if err != nil {
				return err
			}
			txf, err := sdktx.NewFactoryCLI(clientCtx, command.Flags())
			if err != nil {
				return err
			}
			txf, err = txf.Prepare(clientCtx)
			if err != nil {
				return err
			}
			builder, _, err := pqcauthclient.AttachRecoverySignBundle(
				command.Context(),
				clientCtx,
				txf,
				bundle,
			)
			if err != nil {
				return err
			}
			if !clientCtx.SkipConfirm {
				txBytes, err := clientCtx.TxConfig.TxJSONEncoder()(builder.GetTx())
				if err != nil {
					return err
				}
				if err := clientCtx.PrintRaw(json.RawMessage(txBytes)); err != nil {
					_, _ = fmt.Fprintln(command.ErrOrStderr(), string(txBytes))
				}
				ok, err := input.GetConfirmation(
					"confirm revalidated recovery transaction before classical signing and broadcast",
					bufio.NewReader(command.InOrStdin()),
					command.ErrOrStderr(),
				)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("recovery transaction broadcast cancelled")
				}
			}
			if err := sdktx.Sign(txf, clientCtx.GetFromName(), builder, true); err != nil {
				return err
			}
			txBytes, err := clientCtx.TxConfig.TxEncoder()(builder.GetTx())
			if err != nil {
				return err
			}
			response, err := clientCtx.BroadcastTx(txBytes)
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(response)
		},
	}
	flags.AddTxFlagsToCmd(command)
	return command
}

func validateRecoverySigningOptions(
	simulate bool,
	privateKeyPath string,
	bundleOutput string,
) error {
	if privateKeyPath == "" && bundleOutput == "" && !simulate {
		return fmt.Errorf(
			"either --%s or --%s is required",
			flagRecoveryPrivateKey,
			flagRecoveryBundleOutput,
		)
	}
	if privateKeyPath != "" && bundleOutput != "" {
		return fmt.Errorf(
			"--%s and --%s are mutually exclusive",
			flagRecoveryPrivateKey,
			flagRecoveryBundleOutput,
		)
	}
	return nil
}

func printRecoveryBundleReview(
	writer interface{ Write([]byte) (int, error) },
	summary pqcauthclient.RecoverySignBundleSummary,
	transactionJSON []byte,
) {
	_, _ = fmt.Fprintf(
		writer,
		"chain_id: %s\nnetwork_id_base64: %s\nowner: %s\naccount_number: %d\nsequence: %d\nrecovery_key_id: %d\nproposed_signing_key_id: %d\npolicy_version: %d\ntx_sha256: %s\nsign_doc_sha256: %s\ntransaction_json:\n%s\n",
		summary.ChainID,
		base64.StdEncoding.EncodeToString(summary.NetworkID),
		summary.Owner,
		summary.AccountNumber,
		summary.Sequence,
		summary.RecoveryKeyID,
		summary.ProposedSigningKeyID,
		summary.PolicyVersion,
		hex.EncodeToString(summary.TxSHA256),
		hex.EncodeToString(summary.SignDocSHA256),
		transactionJSON,
	)
}

func printRecoveryBundleResult(
	writer interface{ Write([]byte) (int, error) },
	status string,
	path string,
	summary pqcauthclient.RecoverySignBundleSummary,
) error {
	return json.NewEncoder(writer).Encode(recoveryBundleCommandResult{
		Status:               status,
		File:                 path,
		ChainID:              summary.ChainID,
		NetworkID:            base64.StdEncoding.EncodeToString(summary.NetworkID),
		Owner:                summary.Owner,
		AccountNumber:        summary.AccountNumber,
		Sequence:             summary.Sequence,
		RecoveryKeyID:        summary.RecoveryKeyID,
		ProposedSigningKeyID: summary.ProposedSigningKeyID,
		RecoveryAlgorithm:    summary.RecoveryAlgorithm.String(),
		ProposedAlgorithm:    summary.ProposedAlgorithm.String(),
		PolicyVersion:        summary.PolicyVersion,
		TxSHA256:             hex.EncodeToString(summary.TxSHA256),
		SignDocSHA256:        hex.EncodeToString(summary.SignDocSHA256),
		Signed:               summary.Signed,
	})
}
