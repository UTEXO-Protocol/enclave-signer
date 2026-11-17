package evm

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"bridge-utexo/blockchain/networks"
	"bridge-utexo/connectors/burn"
)

func TestSharedBurnCalculationVectors(t *testing.T) {
	path := os.Getenv("BURN_SHARED_VECTORS")
	require.NotEmpty(t, path)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var vectors struct {
		Bridge, Token, RGBNetwork string
		Domain, Burn              map[string]string
		Mints                     []map[string]string
		Settlement                struct{ Encoded string }
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors.Mints, 2)
	decode := func(value string) []byte {
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		require.NoError(t, err)
		return raw
	}
	number := func(value string) *big.Int {
		n, ok := new(big.Int).SetString(value, 10)
		require.True(t, ok)
		return n
	}
	service := settlementService()
	service.config.BridgeContractAddress = common.HexToAddress(vectors.Bridge)
	service.tokenAddress = common.HexToAddress(vectors.Token)
	service.networkID = networks.ID(number(vectors.Domain["chainId"]).Int64())
	rgbNetwork := number(vectors.RGBNetwork).Uint64()
	mints := make([]burn.Mint, 0, len(vectors.Mints))
	for _, mint := range vectors.Mints {
		witness := strings.TrimPrefix(mint["witnessTxidDisplay"], "0x")
		lock, err := burn.MintLockID(mint["opId"], witness)
		require.NoError(t, err)
		require.Equal(t, decode(mint["lockId"]), decode(lock))
		amount := number(mint["amount"]).Uint64()
		id, err := deriveRgbMintDepositID(service.config.BridgeContractAddress,
			uint64(service.networkID), service.tokenAddress, rgbNetwork, [32]byte(decode(lock)), amount)
		require.NoError(t, err)
		require.Equal(t, decode(mint["depositId"]), id[:])
		mints = append(mints, burn.Mint{
			OpID:        mint["opId"],
			WitnessTxID: witness,
			LockID:      lock,
			Amount:      amount,
		})
	}
	release := rgbRelease(mints...)
	release.From.NetworkID = networks.ID(rgbNetwork)
	settlement, err := service.buildSettlement(release)
	require.NoError(t, err)
	require.Equal(t, decode(vectors.Settlement.Encoded), settlement)
	params := FundsOutParams{
		Amount:         number(vectors.Burn["amount"]),
		SourceChainId:  number(vectors.RGBNetwork),
		SourceAddress:  vectors.Burn["sourceAddress"],
		SourceBurnTxId: [32]byte(decode(vectors.Burn["sourceBurnTxId"])),
	}
	id, err := service.deriveBurnIdForService(params)
	require.NoError(t, err)
	require.Equal(t, new(big.Int).SetBytes(decode(vectors.Burn["id"])), id)
}
