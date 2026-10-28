"""Source integration controls. GPU/systemd device actor is substituted; crypto,
archive/source closure, report/schema/oracles/export and /proc predicates are real."""
from pathlib import Path
import contextlib,copy,hashlib,importlib.util,json,os,subprocess,sys,tarfile,tempfile,types,unittest
from unittest import mock
import mesa_official as adapter
import mesa_official_integration as integration
import mesa_runtime as runtime
import mesa_official_reviewed_controls as reviewed
ROOT=Path(__file__).parent
ARCHIVE=ROOT.parent/'mesa/testdata/official-archive.tar.gz'
reviewed.ARCHIVE=ARCHIVE
adapter.SUPERVISOR_PATH=ROOT/'mesa_official_sources/full-supervisor.py'
adapter.GUARD_PATH=ROOT/'mesa_official_sources/admission-supervisor.py'
# Preserve the original18 reviewed controls. They need retained GL/VK ELF pins;
# those binaries are not a new dependency or copied onto any target by tests.
if Path(reviewed.GL).exists() and Path(reviewed.VK).exists():
    ReviewedAdapterControls=reviewed.Adapter

class Integration(unittest.TestCase):
 def fixture(self,d):
    for name in list(sys.modules):
        if name=='omarchy_m_test' or name.startswith('omarchy_m_test.'):del sys.modules[name]
    local=Path(d)/'fixture-archive.tar.gz';local.write_bytes(ARCHIVE.read_bytes())
    with mock.patch.object(reviewed,'ARCHIVE',local):plan,manifest,out,env,pins,vulkan,loader=reviewed.fixture(d)
    out=Path(out);prefix=Path(manifest['prefix']);plan['job']=manifest['job']='j1026-112233-abcd'
    manifest['packages'][0]['name']='mesa-aurora'
    manifest['official_archive']={'path':str(prefix/'official/archive.tar.gz'),'sha256':integration.ARCHIVE_SHA}
    plan['official_sources']={'archive':manifest['official_archive']}
    for role,name,source in [('adapter','mesa_official.py',ROOT/'mesa_official.py'),('integration','mesa_official_integration.py',ROOT/'mesa_official_integration.py'),('supervisor','official/full-supervisor.py',ROOT/'mesa_official_sources/full-supervisor.py'),('guard','official/admission-supervisor.py',ROOT/'mesa_official_sources/admission-supervisor.py')]:
        target=prefix/name;target.write_bytes(source.read_bytes());target.chmod(0o600)
        plan['official_sources'][role]={'path':str(target),'sha256':integration.digest(source.read_bytes())}
    return plan,manifest,out,env,pins
 def actor(self,context_holder,mutation=None):
    def configure(a,raw,plan,manifest,context):
        original_configure(a,raw,plan,manifest,context)
        original_loader=a.load_pinned
        def load(prefix):
            full=original_loader(prefix)
            # Host fixtures cannot chown payload to root. Check all exact
            # archive/member content/mode pins; only the host UID predicate is
            # supplied instead of real target root ownership.
            def verify(data,payload):
                with tarfile.open(fileobj=__import__('io').BytesIO(data)) as t:
                    expected={m.name:(integration.digest(t.extractfile(m).read()),m.mode) for m in t if m.isfile()}
                actual={str(p.relative_to(payload.parent)):(integration.digest(p.read_bytes()),p.stat().st_mode&0o777) for p in payload.parent.rglob('*') if p.is_file()}
                integration.need(actual==expected,'fixture exact archive content/mode drift')
            full.s.verify_staged=verify;return full
        a.load_pinned=load
        def execute(bound):
            bound['cleanup_deadline']=integration.time.monotonic()+60
            if mutation=='deadline':bound.pop('cleanup_deadline')
            context['bound']=bound;context_holder.update(context=context,adapter=a)
            full=a.load_pinned(manifest['prefix']);paths=a.layout_paths(bound);paths['logs'].mkdir(mode=0o700)
            paths['payload_root'].mkdir(mode=0o755)
            with tarfile.open(ARCHIVE) as t:t.extractall(paths['payload_root'],filter='data')
            payload=paths['payload_root']/'omarchy-m-test'
            gpu,schema,bundled=a.load_report_modules(payload)
            impl=a.regular_identity(bound['staged']['vulkan']);loaderpath=next(iter(bound['system_graphics_pins']));ld=a.regular_identity(loaderpath)
            bound['staged_identity']={'vulkan':impl};bound['graphics_before']=bound['system_graphics_pins']
            key=Path(plan['signing_state_home'])/'omarchy-m-test/machine-key';key.unlink();key.with_name('machine-key.pub').unlink()
            # Ephemeral HOST fixture identity only. Production has no keygen.
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
            public=' '.join(key.with_name('machine-key.pub').read_text().split()[:2]);plan['signing_public_sha256']=integration.digest(key.with_name('machine-key.pub').read_bytes());plan['official_identity']['signing'].update(public_sha256=plan['signing_public_sha256'],files=[a.file_metadata(key.parent,'directory'),a.file_metadata(key,'regular'),a.file_metadata(key.with_name('machine-key.pub'),'regular')]);bound['public_identity']=public
            doc=reviewed.document(gpu,plan,impl['sha256'],ld['sha256']);doc.update(document_type='gpu-benchmark',schema_version=1,suite=1,tool={'name':'omarchy-m-test','version':'1.0.0'},stack={'packages':[],'firmware':{}});doc['machine'].update(model='Apple MacBook Air',chip='M1')
            for item in doc['controls']:item['phase']='measured'
            for case in doc['cases']:case['reason']='completed'
            if mutation=='board':doc['machine']['board']='j293'
            if mutation=='partial':doc['cases'][0]['runs'].pop()
            canonical=json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
            signed=subprocess.run(['ssh-keygen','-Y','sign','-f',str(key),'-n',('wrong-namespace' if mutation=='namespace' else full.NAMESPACE)],input=canonical,capture_output=True,check=True).stdout.decode().strip()
            doc['signature']={'public_key':public,'signature':signed}
            if mutation=='signature':
                rows=doc['signature']['signature'].splitlines();rows[1]=('A' if rows[1][0]!='A' else 'B')+rows[1][1:];doc['signature']['signature']='\n'.join(rows)
            blob=(json.dumps(doc,sort_keys=True)+'\n').encode();integration.write_owned(paths['logs']/'gpu-block1.json',blob)
            unit=a.unit_plan(bound);inv='a'*32;state={'Description':full.owner_description(unit),'LimitFSIZE':'4194304','LoadState':'loaded','Transient':'yes','User':str(unit['gui_uid']),'Group':str(unit['gui_gid']),'Type':'exec','RemainAfterExit':'yes','KillMode':'control-group','SendSIGKILL':'yes','TimeoutStopUSec':'5s','RuntimeMaxUSec':'30min','UMask':'0077','InvocationID':inv,'ControlGroup':'','ActiveState':'active','SubState':'exited','MainPID':'0','ExecMainCode':'1','ExecMainStatus':'0','Result':'success'}
            full.owner_check(unit,state,inv)
            cleanup={'stopped':True,'control_group_empty':True,'unit':full.unit_name(unit),'invocation_id':inv}
            for name in integration.ROOT_LOGS:
                value=b''
                if name in ('unit-start.json','unit-before-stop.json'):value=integration.encoded(state)
                if name=='observer-final.json':value=integration.encoded({'cleanup':cleanup,'journal_error':None,'error':None,'fault_categories':[]})
                integration.write_owned(paths['logs']/name,value)
            nodes=[(plan['official_identity']['device']['render_node']['major'],plan['official_identity']['device']['render_node']['minor'])]
            items=[{'pid':1000+i,'birth':2000+i,'workload':w,'negative':n,'implementation':impl,'loader':ld,'renders':nodes.copy()} for i,(w,n) in enumerate(full.expected_schedule(gpu.WORKLOADS))]
            context.update(items=items,clean_exit=True,completions=[a.RetiredEvent(items[0]['pid'],items[0]['birth'],'process')])
            if mutation=='observations':context['items']=items[:-1]
            if mutation=='terminal':context['terminal']={**state,'ExecMainStatus':'7'}
            result=a.seal(paths['logs']/'gpu-block1.json',integration.digest(blob),cleanup,65,{'cryptographic_verification':True,'existing_public_key_matches':True},{'report':str(paths['logs']/'gpu-block1.json'),'journal_final':str(paths['logs']/'journal-final.jsonl'),'observer':str(paths['logs']/'observer-final.json')})
            if mutation=='result':result['native_invocations']=64
            return result
        a.execute=execute
    return configure
 def run_fixture(self,d,mutation=None):
    plan,manifest,out,env,pins=self.fixture(d);ctx={}
    with mock.patch.object(integration,'configure',self.actor(ctx,mutation)),mock.patch.object(integration,'require_current'),mock.patch.object(integration,'module_bytes',side_effect=module_stub_gate):
        result=integration.run_official(plan,manifest,out,env,pins)
    return plan,manifest,out,result,ctx
 def test_connected_dispatch_verifies_real_signature_and_exports_original_report(self):
    with tempfile.TemporaryDirectory() as d:
        plan,m,out,result,context=self.run_fixture(d)
        self.assertEqual(result['status'],'PASS');self.assertEqual(result['native_invocations'],65)
        seal=json.loads((out/result['seal_path']).read_text());self.assertEqual(seal['job'],plan['job']);self.assertEqual(len(seal['files']),14)
        original=Path(m['prefix'])/'official/root/gpu-block1.json';self.assertEqual((out/result['report_path']).read_bytes(),original.read_bytes())
        for name,pin in seal['files'].items():self.assertEqual(integration.digest((out/'official'/name).read_bytes()),pin['sha256'])
        self.assertTrue(json.loads((out/'official/report.json').read_text())['signature']['signature'].startswith('-----BEGIN SSH SIGNATURE-----'))
 def test_mismatch_partial_signature_observation_and_terminal_results_never_seal(self):
    for mutation in ('board','partial','signature','namespace','observations','terminal','result','deadline'):
      with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as d:
        with self.assertRaisesRegex(RuntimeError,'actual-machine-signature' if mutation in ('signature','namespace') else 'report machine|schema|case definition|observations|terminal|cgroup|unsealed|deadline'):self.run_fixture(d,mutation)
        out=Path(d)/'job/out';self.assertFalse((out/'official/seal.json').exists());self.assertTrue((out/'official-failed/failure.json').exists())
 def test_closure_drift_missing_archive_and_symlink_refuse_before_dispatch(self):
    for mutation in ('source','archive','symlink'):
      with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as d:
        p,m,out,e,pins=self.fixture(d)
        if mutation=='source':Path(p['official_sources']['guard']['path']).write_text('unreviewed')
        elif mutation=='archive':m['official_archive']['sha256']='0'*64
        else:
            path=Path(p['official_sources']['guard']['path']);path.unlink();path.symlink_to(ROOT/'mesa_official_sources/admission-supervisor.py')
        with mock.patch.object(integration,'configure') as configure,self.assertRaises(integration.Refuse):integration.run_official(p,m,out,e,pins)
        configure.assert_not_called()
 def test_typed_air_plan_reaches_unit_properties_without_m1_allocation(self):
    with tempfile.TemporaryDirectory() as d:
        p,m,out,e,pins=self.fixture(d);p.update(gui_uid=1001,gui_gid=1001,kernel='7.2.11-7-1-ARCH');raw=integration.source_closure(p,m);a=integration.module_bytes('adapter',raw['adapter']);context={};integration.configure(a,raw,p,m,context);full=a.load_pinned(m['prefix']);bound=a.bind(p,m,out,e,pins)
        self.assertEqual(full.s.KERNEL,p['kernel'])
        for f in (full.validate,full.validate_report,full.s.protected_state):
            with self.assertRaises(integration.Refuse):f({})
        argv=a.launch_argv(full,bound,Path(m['prefix'])/'official/payload/omarchy-m-test',Path(out)/'r',Path(out)/'o',Path(out)/'e')
        self.assertIn('--property=User=1001',argv);self.assertIn('--property=Group=1001',argv);self.assertNotIn('XDG_STATE_HOME=/home/chrisk/.local/state',argv);self.assertIn('XDG_STATE_HOME='+p['signing_state_home'],argv);self.assertFalse(any('7.2.11-6-1-ARCH' in x for x in argv))
 def test_active_typed_identity_rejects_old6_old_m1_board_and_wrong_gui(self):
    with tempfile.TemporaryDirectory() as d:
        p,m,out,e,pins=self.fixture(d);p.update(gui_uid=1001,gui_gid=1001);cmd=b'root=UUID=fixture maclab.job='+p['job'].encode()+b'\n';p['cmdline_sha256']=integration.digest(cmd)
        for problem in ('kernel','board','gui'):
            def text(path,*a,**kw):
                if str(path)=='/proc/sys/kernel/random/boot_id':return p['boot_id']
                if str(path)=='/proc/sys/kernel/osrelease':return '7.2.11-6-1-ARCH' if problem=='kernel' else p['kernel']
                raise AssertionError('unexpected source read '+str(path))
            def data(path):
                if str(path)=='/proc/cmdline':return cmd
                if str(path)=='/proc/device-tree/compatible':return b'apple,j293\0apple,t8103\0' if problem=='board' else b'apple,j313\0apple,t8103\0apple,arm-platform\0'
                raise AssertionError('unexpected source read '+str(path))
            account=types.SimpleNamespace(pw_uid=1000 if problem=='gui' else 1001,pw_gid=1001,pw_dir=p['gui_home'])
            with self.subTest(problem=problem),mock.patch.object(Path,'read_text',text),mock.patch.object(Path,'read_bytes',data),mock.patch.object(integration.pwd,'getpwnam',return_value=account),mock.patch.object(adapter,'recheck_official_identity') as recheck,self.assertRaisesRegex(integration.Refuse,'kernel|board|GUI'):
                integration.require_current(p,adapter,m['prefix'])
            recheck.assert_not_called()
 def test_real_runtime_dispatch_requires_both_legacy_phases_and_complete_official_result(self):
    # Only the dispatch actor is mocked here; separate controls exercise actual
    # source closure, report/schema/crypto, provider and postflight predicates.
    for problem in ('', 'gl', 'vulkan', 'official-partial'):
      with self.subTest(problem=problem), tempfile.TemporaryDirectory() as d:
        p,m,out,e,pins=self.fixture(d);p.update(gui_uid=1001,gui_gid=1001);p['gui_env']['XDG_RUNTIME_DIR']='/run/user/1001';Path(p['manifest_path']).write_text(json.dumps(m));order=[]
        def probe(api,*args):
            order.append(api)
            if api==problem:raise runtime.Stop('fixture legacy failure')
            return {'verdict':'NATIVE_STAGED'}
        def official(*args):
            order.append('official');return {'status':'PASS','native_invocations':64 if problem=='official-partial' else 65,'signature_verified':True}
        account=types.SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_dir=p['gui_home'])
        patches={'render_node':lambda:{},'capture_official_identity':lambda plan:plan['official_identity'],'identity':lambda plan:None,'verify_manifest':lambda *args:None,'system_pins':lambda:pins,'child_env':lambda *args:e,'health':lambda plan:{'stable':True},'capture':lambda *args:b'installed package fixture','probe':probe,'verify_system':lambda pins:None}
        with contextlib.ExitStack() as stack:
            for name,value in patches.items():stack.enter_context(mock.patch.object(runtime,name,value))
            stack.enter_context(mock.patch.object(runtime.os,'geteuid',return_value=0));stack.enter_context(mock.patch.object(runtime.os,'chown'));stack.enter_context(mock.patch.object(runtime.pwd,'getpwnam',return_value=account));stack.enter_context(mock.patch.object(integration,'source_closure',side_effect=lambda *args:order.append('closure')));stack.enter_context(mock.patch.object(integration,'run_official',side_effect=official))
            if problem:
                with self.assertRaisesRegex(runtime.Stop,'fixture legacy failure|official suite incomplete'):runtime.run(p,out)
                self.assertEqual(json.loads((out/'mesa-result.json').read_text())['verdict'],'FAIL')
            else:self.assertEqual(runtime.run(p,out)['verdict'],'PASS')
        self.assertEqual(order, {'':['closure','gl','vulkan','official'],'gl':['closure','gl'],'vulkan':['closure','gl','vulkan'],'official-partial':['closure','gl','vulkan','official']}[problem])
 def test_export_bounds_types_and_root_cannot_adopt_gui_owned_output(self):
    with tempfile.TemporaryDirectory() as d:
        root=Path(d)
        with self.assertRaises(integration.Refuse):integration.write_owned(root/'too-large',b'x'*(integration.MAX_FILE+1))
        self.assertFalse((root/'too-large').exists())
        fifo=root/'fifo';os.mkfifo(fifo);opened=[];real=os.open
        def opened_(path,flags,*a,**kw):opened.append(flags);return real(path,flags,*a,**kw)
        with mock.patch.object(integration.os,'open',opened_),self.assertRaises(integration.Refuse):integration.read_owned(fifo)
        self.assertTrue(opened);self.assertTrue(all(flags&os.O_PATH for flags in opened))
        if os.geteuid()!=0:
            with mock.patch.object(integration.os,'geteuid',return_value=0),self.assertRaises(integration.Refuse):integration.write_owned(root/'not-root-owned',b'no')
            self.assertFalse((root/'not-root-owned').exists())
 def test_root_export_rejects_symlink_parent_and_forged_bytes(self):
    with tempfile.TemporaryDirectory() as d:
        root=Path(d);(root/'real').mkdir();(root/'alias').symlink_to(root/'real')
        with self.assertRaises(integration.Refuse):integration.write_owned(root/'alias/report.json',b'bad')
        self.assertFalse((root/'real/report.json').exists())

original_configure=integration.configure
original_module=integration.module_bytes
def module_stub_gate(name,raw):
    module=original_module(name,raw)
    if name=='staged_reviewed_mesa_official':module.execution_gate=lambda plan:None
    return module
