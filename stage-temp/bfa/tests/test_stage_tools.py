import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
from config import read_config
from deploy_host import edit_env, exact_cids
from identity import compare, KEY_FIELDS, POLICY_FIELDS
import seed_store
from verify_bundle import verify, NAMES, digest

class StageTools(unittest.TestCase):
    def test_config_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'config.json'
            for value, allowed in [({'mode':'bootstrap','rgb_asset_id':''}, True),
                                   ({'mode':'configured','rgb_asset_id':'rgb:fixture'}, True),
                                   ({'mode':'configured','rgb_asset_id':''}, False),
                                   ({'mode':'bootstrap','rgb_asset_id':'rgb:fixture'}, False),
                                   ({'mode':'bootstrap','rgb_asset_id':'','seed':'secret'}, False)]:
                file.write_text(json.dumps(value))
                if allowed:
                    self.assertEqual(read_config(file), value)
                else:
                    with self.assertRaises(ValueError): read_config(file)

    def test_environment_edit_keeps_tls_and_routing(self):
        before = 'CLUSTER_DIR=/old\nGRPC_TLS_KEY_FILE=/tls/key.pem\nEVM_NETWORK_IDS=84\n# note\n'
        self.assertEqual(edit_env(before, {'CLUSTER_DIR':'/new'}),
                         'GRPC_TLS_KEY_FILE=/tls/key.pem\nEVM_NETWORK_IDS=84\n# note\nCLUSTER_DIR=/new\n')

    def test_exact_instance_set(self):
        good = [{'EnclaveCID':cid,'State':'RUNNING'} for cid in (16,18,20)]
        exact_cids(good)
        for bad in ([], good[:2], good+[good[0]], good+[{'EnclaveCID':22,'State':'RUNNING'}]):
            with self.assertRaises(ValueError): exact_cids(bad)

    def test_key_restore_compares_every_signer(self):
        before = {str(cid):{field:'fixture' for field in KEY_FIELDS+POLICY_FIELDS} for cid in (16,18,20)}
        after = json.loads(json.dumps(before))
        compare(before, after, True)
        after['18']['RGB asset id'] = 'rgb:configured'
        compare(before, after, False)
        with self.assertRaises(ValueError): compare(before, after, True)
        after['20']['Account xpub colored'] = 'wrong-key'
        with self.assertRaises(ValueError): compare(before, after, False)
        with self.assertRaises(ValueError): compare(before, {}, False)

    def test_bundle_rejects_tampering_missing_duplicate_and_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in NAMES: (directory/name).write_text('fixture')
            metadata = dict(variant='stage-bfa-temp',security_policy='Development',runtime_debug_required=True,
                            cargo_profile='stage-bfa-temp',mode='bootstrap',rgb_asset_id='')
            (directory/'metadata.json').write_text(json.dumps(metadata))
            good = ''.join(f'{digest(directory/n)}  {n}\n' for n in sorted(NAMES))
            manifest = directory/'BUNDLE-SHA256SUMS'
            manifest.write_text(good)
            expected = digest(manifest)
            self.assertEqual(verify(directory,expected,describe=False),metadata)
            (directory/'stage-bfa-temp.eif').write_text('tampered')
            with self.assertRaises(ValueError): verify(directory,expected,describe=False)
            (directory/'stage-bfa-temp.eif').write_text('fixture')
            for bad in (good+good.splitlines()[0]+'\n', '\n'.join(good.splitlines()[1:])+'\n',
                        good.replace('  PCR.json', '  ../PCR.json')):
                manifest.write_text(bad)
                with self.assertRaises(ValueError): verify(directory,digest(manifest),describe=False)

    def test_seed_creation_is_distinct_and_never_overwrites(self):
        calls = []
        def fake_aws(args,payload=None):
            calls.append((args,payload))
            return {'Version':1}
        args = types.SimpleNamespace(prefix='/utexo/stage-temp/bfa/test',kms_key_id='test-key',cid=None)
        with patch.object(seed_store,'aws',fake_aws), patch('builtins.print'):
            seed_store.create(args)
        values = [json.loads(payload['Value']) for _,payload in calls]
        self.assertEqual(len({v['seed_hex'] for v in values}),3)
        self.assertEqual(len({v['cloning_secret'] for v in values}),3)
        self.assertTrue(all(len(v['seed_hex']) == 128 for v in values))
        self.assertTrue(all(payload['Overwrite'] is False for _,payload in calls))
        self.assertTrue(all('file:///dev/stdin' in args for args,_ in calls))
        with self.assertRaises(ValueError): seed_store.parameter('/prod/keys',16)

    def test_aws_diagnostics_do_not_echo_payload(self):
        failed = types.SimpleNamespace(returncode=1,stdout='',stderr='PRIVATE-SEED-VALUE')
        with patch.object(seed_store.subprocess,'run',return_value=failed):
            with self.assertRaises(RuntimeError) as result: seed_store.aws(['ssm','put-parameter'])
        self.assertNotIn('PRIVATE-SEED-VALUE',str(result.exception))

if __name__ == '__main__': unittest.main()
