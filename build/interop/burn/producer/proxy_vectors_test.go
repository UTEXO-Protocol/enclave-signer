package blsproxy

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedBurnCalculationVectors(t *testing.T) {
	path := os.Getenv("BURN_SHARED_VECTORS")
	require.NotEmpty(t, path)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var vectors struct {
		Domain   map[string]string
		Releases []struct {
			Name, Route, Nonce, Deadline string
			Expected                     map[string]string
		}
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors.Releases, 2)
	for _, vector := range vectors.Releases {
		t.Run(vector.Name, func(t *testing.T) {
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
			tr := &transactor{domainSeparator: [32]byte(decode(vectors.Domain["separator"]))}
			parse, encode := parseFundsOutCallData, buildFundsOutCallData
			hash, digest := fundsOutStructHash, tr.buildFundsOutDigest
			typeHash := teeFundsOutTypehash
			switch vector.Route {
			case "direct":
			case "layerzero":
				parse, encode = parseLzFundsOutCallData, buildLzFundsOutCallData
				hash, digest = lzFundsOutStructHash, tr.buildLzFundsOutDigest
				typeHash = teeLzFundsOutTypehash
			default:
				t.Fatalf("unknown shared route %q", vector.Route)
			}
			calldata := decode(vector.Expected["calldata"])
			params, err := parse(calldata)
			require.NoError(t, err)
			rebuilt, err := encode(params)
			require.NoError(t, err)
			require.Equal(t, calldata, rebuilt)
			nonce, deadline := number(vector.Nonce), number(vector.Deadline)
			require.Equal(t, decode(vector.Expected["typeHash"]), typeHash.Bytes())
			require.Equal(t, decode(vector.Expected["structHash"]), hash(params, nonce, deadline))
			require.Equal(t, decode(vector.Expected["digest"]), digest(params, nonce, deadline))
		})
	}
}
