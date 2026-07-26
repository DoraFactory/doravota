package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/input"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
)

type bundleCommandResult struct {
	Status        string `json:"status"`
	File          string `json:"file"`
	ChainID       string `json:"chain_id"`
	NetworkID     string `json:"network_id_base64"`
	Signer        string `json:"signer"`
	AccountNumber uint64 `json:"account_number"`
	Sequence      uint64 `json:"sequence"`
	KeyID         uint64 `json:"key_id"`
	Algorithm     string `json:"algorithm"`
	PolicyVersion uint64 `json:"policy_version"`
	TxSHA256      string `json:"tx_sha256"`
	SignDocSHA256 string `json:"sign_doc_sha256"`
	Signed        bool   `json:"signed"`
}

func prepareBundleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "prepare-bundle [generate-only-tx-json] [prepared-bundle-output]",
		Short: "Freeze any generated single-signer transaction for offline PQC signing",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			if clientCtx.Offline || clientCtx.GenerateOnly || clientCtx.Simulate {
				return errors.New("prepare-bundle requires an online, non-simulation client")
			}
			if err := rejectBundledTxMutationFlags(command.Flags()); err != nil {
				return err
			}
			unsignedJSON, err := readRegularFile(
				args[0],
				pqcauthclient.MaxUnsignedTxJSONBytes,
				"unsigned transaction JSON",
			)
			if err != nil {
				return err
			}
			builder, err := pqcauthclient.DecodeUnsignedTxJSONForPQCBundle(
				clientCtx.TxConfig,
				unsignedJSON,
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
			bundle, summary, err := pqcauthclient.PreparePQCSignBundle(
				command.Context(),
				clientCtx,
				txf,
				builder,
			)
			if err != nil {
				return err
			}
			encoded, err := pqcauthclient.MarshalPQCSignBundle(
				clientCtx.TxConfig,
				bundle,
				false,
			)
			if err != nil {
				return err
			}
			if err := writeNewFileAtomic(args[1], encoded, 0o600); err != nil {
				return err
			}
			return printBundleResult(
				command.OutOrStdout(),
				"prepared",
				args[1],
				summary,
			)
		},
	}
	flags.AddTxFlagsToCmd(command)
	return command
}

func signBundleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "sign-bundle [prepared-bundle] [private-key-file] [signed-bundle-output]",
		Short: "Validate and sign a prepared transaction bundle on an offline machine",
		Args:  cobra.ExactArgs(3),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(command)
			encoded, err := readBundleFile(args[0])
			if err != nil {
				return err
			}
			bundle, summary, err := pqcauthclient.UnmarshalPQCSignBundle(
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
					return fmt.Errorf("decode transaction for offline review: %w", err)
				}
				transactionJSON, err := clientCtx.TxConfig.TxJSONEncoder()(decodedTx)
				if err != nil {
					return fmt.Errorf("encode transaction for offline review: %w", err)
				}
				printBundleReview(command.ErrOrStderr(), summary, transactionJSON)
				ok, err := input.GetConfirmation(
					"confirm exact transaction hashes before offline ML-DSA signing",
					bufio.NewReader(command.InOrStdin()),
					command.ErrOrStderr(),
				)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("offline PQC signing cancelled")
				}
			}
			privateKey, err := pqcauthclient.LoadPrivateKeyFile(args[1])
			if err != nil {
				return err
			}
			defer clear(privateKey)
			signed, signedSummary, err := pqcauthclient.SignPQCSignBundleWithPrivateKey(
				command.Context(),
				clientCtx.TxConfig,
				bundle,
				privateKey,
			)
			if err != nil {
				return err
			}
			signedBytes, err := pqcauthclient.MarshalPQCSignBundle(
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
			return printBundleResult(command.OutOrStdout(), "signed", args[2], signedSummary)
		},
	}
	command.Flags().BoolP(flags.FlagSkipConfirmation, "y", false, "Skip offline signing confirmation")
	return command
}

func broadcastBundleCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "broadcast-bundle [signed-bundle]",
		Short: "Revalidate, classically sign, and broadcast an offline-signed PQC bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(command)
			if err != nil {
				return err
			}
			if clientCtx.Offline || clientCtx.GenerateOnly || clientCtx.Simulate {
				return errors.New("broadcast-bundle requires an online, non-simulation client")
			}
			if err := rejectBundledTxMutationFlags(command.Flags()); err != nil {
				return err
			}
			encoded, err := readBundleFile(args[0])
			if err != nil {
				return err
			}
			bundle, _, err := pqcauthclient.UnmarshalPQCSignBundle(
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
			builder, _, err := pqcauthclient.AttachPQCSignBundle(
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
					"confirm revalidated protected transaction before classical signing and broadcast",
					bufio.NewReader(command.InOrStdin()),
					command.ErrOrStderr(),
				)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("protected transaction broadcast cancelled")
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

func readBundleFile(path string) ([]byte, error) {
	return readRegularFile(path, pqcauthclient.MaxPQCSignBundleBytes, "PQC sign bundle")
}

func readRegularFile(path string, maxBytes int, label string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if info.Size() <= 0 || info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf(
			"%s length must be between 1 and %d bytes",
			label,
			maxBytes,
		)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(maxBytes+1)))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if len(encoded) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	return encoded, nil
}

// writeNewFileAtomic publishes a fully synced file without ever replacing an
// existing destination. A same-directory hard link provides the atomic,
// no-clobber publication step.
func writeNewFileAtomic(path string, contents []byte, permissions os.FileMode) error {
	cleanPath := filepath.Clean(path)
	directory := filepath.Dir(cleanPath)
	base := filepath.Base(cleanPath)
	temp, err := os.CreateTemp(directory, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary output file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
	}()
	if err := temp.Chmod(permissions); err != nil {
		return fmt.Errorf("set output file permissions: %w", err)
	}
	if _, err := temp.Write(contents); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync output file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}
	closed = true
	if err := os.Link(tempPath, cleanPath); err != nil {
		return fmt.Errorf("publish output without overwrite: %w", err)
	}
	if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf("remove temporary output link: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open output directory for sync: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}

func rejectBundledTxMutationFlags(flagSet *pflag.FlagSet) error {
	for _, name := range []string{
		flags.FlagAccountNumber,
		flags.FlagSequence,
		flags.FlagNote,
		flags.FlagFees,
		flags.FlagGasPrices,
		flags.FlagGas,
		flags.FlagGasAdjustment,
		flags.FlagTimeoutHeight,
		flags.FlagFeePayer,
		flags.FlagFeeGranter,
		flags.FlagTip,
		flags.FlagAux,
		flags.FlagDryRun,
		flags.FlagGenerateOnly,
		flags.FlagOffline,
		flags.FlagSignMode,
	} {
		if flagSet.Changed(name) {
			return fmt.Errorf("--%s cannot override fields frozen in a PQC sign bundle", name)
		}
	}
	return nil
}

func printBundleReview(
	writer io.Writer,
	summary pqcauthclient.PQCSignBundleSummary,
	transactionJSON []byte,
) {
	_, _ = fmt.Fprintf(
		writer,
		"chain_id: %s\nnetwork_id_base64: %s\nsigner: %s\naccount_number: %d\nsequence: %d\nkey_id: %d\npolicy_version: %d\ntx_sha256: %s\nsign_doc_sha256: %s\ntransaction_json:\n%s\n",
		summary.ChainID,
		base64.StdEncoding.EncodeToString(summary.NetworkID),
		summary.Signer,
		summary.AccountNumber,
		summary.Sequence,
		summary.KeyID,
		summary.PolicyVersion,
		hex.EncodeToString(summary.TxSHA256),
		hex.EncodeToString(summary.SignDocSHA256),
		transactionJSON,
	)
}

func printBundleResult(
	writer io.Writer,
	status string,
	path string,
	summary pqcauthclient.PQCSignBundleSummary,
) error {
	return json.NewEncoder(writer).Encode(bundleCommandResult{
		Status:        status,
		File:          path,
		ChainID:       summary.ChainID,
		NetworkID:     base64.StdEncoding.EncodeToString(summary.NetworkID),
		Signer:        summary.Signer,
		AccountNumber: summary.AccountNumber,
		Sequence:      summary.Sequence,
		KeyID:         summary.KeyID,
		Algorithm:     summary.Algorithm.String(),
		PolicyVersion: summary.PolicyVersion,
		TxSHA256:      hex.EncodeToString(summary.TxSHA256),
		SignDocSHA256: hex.EncodeToString(summary.SignDocSHA256),
		Signed:        summary.Signed,
	})
}
