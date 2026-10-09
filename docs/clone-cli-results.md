# `clone` CLI results

`utexo-bridge-parent-cli clone` prints one result line on stdout:
`CLONE_RESULT_V1=<result>`. It prints the detail on stderr. Automation must
read the result line, not the exit code alone. Source:
`parent/src/bin/cli.rs` and `parent/src/bin/cli/clone_completion.rs`.

| Result | Meaning | Exit code |
| --- | --- | --- |
| `success` | `SetClone` was acknowledged. The new enclave has the donor's EVM address and all 13 identity fields. | 0 |
| `recovered_success` | The `SetClone` reply was an error, lost or late. The read-back shows the donor's identity. | 0 |
| `identity_mismatch` | The new enclave has keys, but they differ from the donor's. | 1 |
| `not_initialized` | `SetClone` returned an error and the new enclave has no keys at the read-back. This is not a final state. Do not retry `SetClone` blindly. | 1 |
| `unknown` | The CLI could not read the identity back. Check the enclave read-only. Do not retry `SetClone` automatically. | 1 |
| `preflight_error` | The command failed before it sent `SetClone`, for example no cloning secret or a donor bundle that does not match `--donor-evm`. | 1 |

The CLI waits at most 1.5 seconds for `SetClone` and the read-back. A
timeout does not cancel `SetClone` and does not prove that it failed.
