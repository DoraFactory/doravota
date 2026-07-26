package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/input"
	sdktx "github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/pflag"

	pqcauthclient "github.com/DoraFactory/doravota/x/pqcauth/client"
)

func generateOrBroadcastProtectedTx(
	ctx context.Context,
	clientCtx client.Context,
	flagSet *pflag.FlagSet,
	privateKeyPath string,
	messages ...sdk.Msg,
) error {
	bundleOutput, _ := flagSet.GetString(flagPQCSignBundleOutput)
	if err := validateProtectedSigningOptions(
		clientCtx.Simulate,
		privateKeyPath,
		bundleOutput,
	); err != nil {
		return err
	}
	if clientCtx.GenerateOnly {
		return errors.New("use --pqc-sign-bundle-output to prepare a protected transaction for offline signing")
	}
	for _, message := range messages {
		if err := message.ValidateBasic(); err != nil {
			return err
		}
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
			return errors.New("cannot estimate gas in offline mode")
		}
		simulationExtension, err := pqcauthclient.BuildPQCAuthSimulationExtension(
			ctx,
			clientCtx,
		)
		if err != nil {
			return err
		}
		simulationFactory := txf.WithExtensionOptions(simulationExtension)
		_, adjusted, err := sdktx.CalculateGas(
			clientCtx,
			simulationFactory,
			messages...,
		)
		if err != nil {
			return err
		}
		txf = txf.WithGas(adjusted)
		_, _ = fmt.Fprintf(os.Stderr, "gas estimate: %d\n", adjusted)
	}
	if clientCtx.Simulate {
		return nil
	}

	builder, err := txf.BuildUnsignedTx(messages...)
	if err != nil {
		return err
	}
	if bundleOutput != "" {
		if clientCtx.Offline {
			return errors.New("PQC sign bundle preparation requires online policy lookup")
		}
		bundle, summary, err := pqcauthclient.PreparePQCSignBundle(
			ctx,
			clientCtx,
			txf,
			builder,
		)
		if err != nil {
			return err
		}
		encoded, err := pqcauthclient.MarshalPQCSignBundle(clientCtx.TxConfig, bundle, false)
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
		return printBundleResult(output, "prepared", bundleOutput, summary)
	}
	privateKey, err := pqcauthclient.LoadPrivateKeyFile(privateKeyPath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	if err := pqcauthclient.AttachPQCAuthWithPrivateKey(
		ctx,
		clientCtx,
		txf,
		builder,
		privateKey,
	); err != nil {
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
			"confirm protected transaction before classical signing and broadcast",
			bufio.NewReader(os.Stdin),
			os.Stderr,
		)
		if err != nil || !ok {
			return err
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

func validateProtectedSigningOptions(
	simulate bool,
	privateKeyPath string,
	bundleOutput string,
) error {
	if privateKeyPath == "" && bundleOutput == "" && !simulate {
		return fmt.Errorf(
			"either --%s or --%s is required",
			flagPQCPrivateKey,
			flagPQCSignBundleOutput,
		)
	}
	if privateKeyPath != "" && bundleOutput != "" {
		return fmt.Errorf(
			"--%s and --%s are mutually exclusive",
			flagPQCPrivateKey,
			flagPQCSignBundleOutput,
		)
	}
	return nil
}
