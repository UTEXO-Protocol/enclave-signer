// Testing-only process boundary: production code never imports this AGPL tool.
// One JSON Simulation object per stdin line; one compact verdict per stdout line.
import { createInterface } from 'node:readline';
import { runSimulation, runUnsafeSimulation } from '@actsecurity/iam-simulate';
import { createValidatedPolicy, validateResourcePolicy } from '@actsecurity/iam-policy';

for await (const line of createInterface({ input: process.stdin })) {
  try {
    const simulation = JSON.parse(line);
    simulation.resourcePolicy = createValidatedPolicy(
      simulation.resourcePolicy, validateResourcePolicy, { name: 'production-resource-policy' }
    );
    const result = await runSimulation(simulation, { simulationMode: 'Strict' });
    // iam-data 0.21.202609121 reports the parameterized EncryptionContext name
    // differently from this version's admission filter. runSimulation silently
    // drops valid kms:EncryptionContext:<key> inputs. The public unfiltered entry
    // point uses the SAME Strict authorizer and condition operators. Preserve
    // those AWS-defined request keys instead of changing production policies.
    const ignored = result.result?.ignoredContextKeys || [];
    // Negative policy cases may deliberately include attestation context on an
    // alternate action (e.g. Encrypt); preserve it for the same Strict engine.
    const knownKmsContext = k => k.startsWith('kms:EncryptionContext:') ||
      k === 'kms:EncryptionContextKeys' || k === 'kms:RecipientAttestation:PCR0';
    const unexpected = ignored.filter(k => !knownKmsContext(k));
    if (unexpected.length) throw new Error(`Unexpected ignored context keys: ${unexpected.join(', ')}`);
    const retainContext = result.resultType !== 'error' && ignored.length > 0;
    const verdict = retainContext ? runUnsafeSimulation(simulation, {}) : result.overallResult;
    const analysis = retainContext ? undefined : result.result?.analysis;
    const decisive = (group) => (group?.denyStatements || []).map(s => s.explain?.identifier);
    process.stdout.write(JSON.stringify({
      resultType: result.resultType,
      result: verdict,
      retainedContextKeys: retainContext ? ignored : [],
      errors: result.errors,
      identityDeny: decisive(analysis?.identityAnalysis),
      resourceDeny: decisive(analysis?.resourceAnalysis)
    }) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ resultType: 'error', errors: String(error) }) + '\n');
  }
}
