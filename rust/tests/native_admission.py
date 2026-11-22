import json,sqlite3,subprocess,pathlib,os,sys,time,hashlib
X=json.load(open(sys.argv[1]));BIN=sys.argv[2];ROOT=pathlib.Path(sys.argv[3]);ROOT.mkdir(exist_ok=True);ROOT=ROOT.resolve()
C=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
cs=[dict(binding=e['trusted_binding'],evidence_id=json.loads(e['request']['utf8'])['evidence_id'],artifact_utf8=e['artifact']['utf8']) for e in X['events'].values()]
results=[];calls=0
def call(p,op,**kw):
 global calls
 calls+=1
 q=dict(path=str(p),op=op,captures=kw.pop("captures",cs),**kw);env=os.environ.copy();fault=q.pop('fault',None)
 if fault:env['VORDA_NATIVE_FAULT']=fault
 t=time.monotonic();r=subprocess.run([BIN],input=C(q),text=True,capture_output=True,env=env)
 evidence=ROOT/('call-%03d'%calls);evidence.mkdir();(evidence/'request.json').write_text(C(q));(evidence/'stdout').write_text(r.stdout);(evidence/'stderr').write_text(r.stderr);(evidence/'exit.json').write_text(C(dict(exit=r.returncode,elapsed=time.monotonic()-t,fault=fault)));print(op,r.returncode,r.stdout[:150],flush=True)
 if r.returncode==86:return None
 try:v=json.loads(r.stdout)
 except:raise AssertionError((r.returncode,r.stdout,r.stderr))
 return v

def seed(name):
 p=ROOT/(name+'.db');db=sqlite3.connect(p);db.executescript(X['baseline_ddl']);db.execute('pragma user_version=1')
 for table,rows in X['legacy']['hub_rows'].items():
  for row in rows:
   values=[v['blob_utf8'].encode() if isinstance(v,dict) else v for v in row];db.execute('insert into '+table+' values('+','.join('?' for _ in values)+')',values)
 db.execute('insert into batches values(?,?,?,?)',('legacy-device',7,'digest',b'\x00ack\xff'));db.commit();db.close()
 out=sqlite3.connect(str(p)+'.outbox');out.executescript(X['outbox_ddl']);out.execute('pragma user_version=1');out.execute('insert into identity values(?,?,?)',X['legacy']['identity_row']);out.execute('insert into pending values(?,?,?,?)',(7,X['legacy']['queue']['utf8'].encode(),2,0));out.commit();out.close();return p

def submit(p,name,seq=None,clock='1793898320',fault=None):
 raw=X['events'][name]['request']['utf8']
 if seq: q=json.loads(raw);q['sequence']=seq;raw=C(q)
 return call(p,'admit',request=raw,clock=clock,fault=fault)
def view(p,a='A'):return json.loads(call(p,'view',binding=X['trusted_configurations'][a])['ok'])
def case(name,fn):
 if len(sys.argv)>4 and name!=sys.argv[4]:return
 try:fn();results.append(dict(case=name,result='PASS'))
 except Exception as e:results.append(dict(case=name,result='FAIL',error=repr(e)));print('FAIL',name,repr(e),flush=True)
 (ROOT/'results.json').write_text(json.dumps(results,indent=2))
def base(name):p=seed(name);assert call(p,'migrate')=={'ok':True};return p

def independent():
 p=base('independent')
 for name in ['A1','A2','B1','G1']:
  r=submit(p,name);assert r['ok']==X['events'][name]['ack']['utf8'],(name,r)
 for name in ['A1','B1','G1']:assert submit(p,name,clock='1793898400')['ok']==X['events'][name]['ack']['utf8']
 assert submit(p,'B2')['ok']
 db=sqlite3.connect(p)
 expected=X['cases'][0]['expected']
 for name,state in expected['authorities'].items():
  b=X['trusted_configurations'][name];a=C([b[k] for k in ['tenant','site','device','generation','scope']]);frontier,delivery,publication=db.execute('select frontier,delivery_frontier,publication from v2_authorities where authority=?',(a,)).fetchone();assert frontier==state['frontier'];assert delivery==expected['delivery_frontiers'][name];assert publication==expected['publication_ordinals'][name]
  assert dict((path,[record]) for path,record in db.execute('select path,record from v2_current where authority=?',(a,)))==state['current']
  assert sorted(row[0] for row in db.execute('select record from v2_observations where authority=?',(a,)))==sorted(state['history'])
  coverage=dict((path,'revision%d:%s'%(rev,json.loads(payload)['state'])) for path,rev,payload in db.execute('select c.path,s.revision,c.payload from v2_coverage c join v2_assessments s on s.authority=c.authority and s.assessment=c.assessment where c.authority=?',(a,)));assert coverage==state['latest_coverage']
  assert set(row[0] for row in db.execute('select received from v2_assessments where authority=?',(a,)))=={'1793898320'}
 db.close()
 assert C(view(p))==X['events']['A2']['view']['utf8'];assert C(view(p,'G'))==X['events']['G1']['view']['utf8']
case('independent-authorities',independent)
def replay():
 p=base('replay');submit(p,'A1');submit(p,'A2');r=submit(p,'A1',3,clock='1793898400');assert r['ok']==X['variants']['A1-sequence3-reexport']['ack']['utf8'];assert C(view(p))==X['events']['A2']['view']['utf8']
case('new-sequence-reexport',replay)
def evidence_rebind():
 p=base('evidence-rebind');assert 'ok' in submit(p,'A1');before=p.read_bytes();q=json.loads(X['events']['A1']['request']['utf8']);q['sequence']=2;q['evidence_id']='unconfigured-rebound-evidence';r=call(p,'admit',request=C(q));assert r=={'error':'assessment_conflict','status':409},r;assert p.read_bytes()==before;assert submit(p,'A1',2)['ok']
case('replay-evidence-rebind-refused',evidence_rebind)

def reverse():
 p=base('reverse');submit(p,'A2');r=submit(p,'A1',3);assert json.loads(r['ok'])['result']=='historical_only';assert len(view(p)['records'])==1
case('reverse-order',reverse)
for point in ['before-commit','after-commit-before-response']:
 def crash(point=point):
  p=base(point);submit(p,'A1');assert submit(p,'A2',fault=point) is None;v=view(p);assert v['header']['snapshot_revision']==(1 if point=='before-commit' else 2);r=submit(p,'A2',clock='1793898400');ack=json.loads(r['ok']);assert ack['received_at']==('1793898400' if point=='before-commit' else '1793898320')
 case(point,crash)
for point in ['before-backup-verified','after-backup-before-begin','after-first-create','after-all-create','after-version-before-commit','after-commit-before-verification']:
 def migration(point=point):
  p=seed(point);outbox=pathlib.Path(str(p)+'.outbox').read_bytes();db=sqlite3.connect(p);old={table:db.execute('select * from '+table).fetchall() for table in X['legacy']['hub_rows']};db.close();assert call(p,'migrate',fault=point) is None;assert call(p,'migrate')=={'ok':True};db=sqlite3.connect(p);assert db.execute('pragma user_version').fetchone()[0]==2;assert db.execute("select ack from batches where device='legacy-device'").fetchone()[0]==b'\x00ack\xff';assert old=={table:db.execute('select * from '+table).fetchall() for table in X['legacy']['hub_rows']};assert outbox==pathlib.Path(str(p)+'.outbox').read_bytes();assert sum(db.execute('select count(*) from '+t).fetchone()[0] for t in ['v2_authorities','v2_assessments','v2_observations','v2_current','v2_coverage','v2_deliveries','v2_views'])==0;db.close()
 case('migration-'+point,migration)
def newer():
 p=seed('newer');db=sqlite3.connect(p);db.execute('pragma user_version=3');db.close();b=p.read_bytes();assert call(p,'migrate')['error']=='unsupported_link_schema';assert b==p.read_bytes()
case('newer-schema-refusal',newer)
def restore(bad=False):
 p=base('badrestore' if bad else 'restore');before=p.read_bytes()
 if bad:b=pathlib.Path(str(p)+'.v1-backup');data=bytearray(b.read_bytes());data[0]^=1;b.write_bytes(data)
 r=call(p,'restore')
 if bad:assert r['error']=='backup_integrity_failure';assert p.read_bytes()==before
 else:assert r=={'ok':True};db=sqlite3.connect(p);assert db.execute('pragma user_version').fetchone()[0]==1;db.close()
case('backup-restore',restore);case('bad-backup-refusal',lambda:restore(True))
for name,v in X['variants'].items():
 if name.startswith('bad-v2-ack-'):
  def badack(v=v):assert 'error' in call(ROOT/'unused','ack',request=X['events']['A1']['request']['utf8'],ack=v['ack']['utf8'])
  case(name.replace('bad-v2-ack-','v2-bad-ack-'),badack)

# Framing and body negatives call only the public in-memory trial adapter.
for spec in X['cases']:
 name=spec['id']
 if name not in ['oversize-before-read','duplicate-content-length','transfer-encoding','body-truncated','extra-body-object','duplicate-envelope-key','duplicate-artifact-key','over-depth','string-over-limit','unsupported-schema']:continue # 'third-input' dropped: the hub now takes up to 256 inputs (hub_full_assessments.rs pins that)
 def malformed(name=name,spec=spec):
  p=base(name);q=json.loads(X['events']['A1']['request']['utf8']);body=C(q);extra=[];length=None
  if name=='oversize-before-read':length=4259841;body='' # one byte over the 4 MiB + 64 KiB request bound
  elif name=='duplicate-content-length':extra=['content-length: '+str(len(body.encode()))]
  elif name=='transfer-encoding':extra=['Transfer-Encoding: chunked']
  elif name=='body-truncated':length=len(body.encode())+1
  elif name=='extra-body-object':body+='{}'
  elif name=='duplicate-envelope-key':body='{"schema":2,'+body[1:]
  elif name=='unsupported-schema':q['schema']=3;body=C(q)
  else:
   a=json.loads(q['artifact_utf8'])
   if name=='duplicate-artifact-key':raw='{"revision":1,'+q['artifact_utf8'][1:]
   elif name=='over-depth':raw='['*17+'0'+']'*17
   else:
    if name=='string-over-limit':a['producer']['name']='x'*4097
    raw=C(a)
   q['artifact_utf8']=raw;q['artifact_byte_length']=len(raw.encode());q['artifact_sha256']=hashlib.sha256(raw.encode()).hexdigest();body=C(q)
  headers=['Host: trial','Content-Type: application/json','Authorization: Bearer trusted-local','Content-Length: '+str(length if length is not None else len(body.encode()))]+extra
  http='POST /v2/batches HTTP/1.1\r\n'+'\r\n'.join(headers)+'\r\n\r\n'+body
  r=call(p,'http',request=http);assert r.get('status')==spec['expected']['http_status'],r
  db=sqlite3.connect(p);assert db.execute('select count(*) from v2_deliveries').fetchone()[0]==0;db.close()
 case(name,malformed)
# An actually held admission across processes must refuse a second admission.
def busy():
 p=base('busy');fifo=ROOT/'hold.fifo';os.mkfifo(fifo);q=dict(path=str(p),op='admit',captures=cs,request=X['events']['A1']['request']['utf8']);env=os.environ.copy();env['VORDA_NATIVE_HOLD_FIFO']=str(fifo)
 first=subprocess.Popen([BIN],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env);first.stdin.write(C(q));first.stdin.close();assert first.stdout.readline().strip()=='held'
 try:assert submit(p,'A1').get('status')==503
 finally:
  with open(fifo,'w') as f:f.write('x')
 assert first.wait(timeout=5)==0;(ROOT/'busy-first.stdout').write_text(first.stdout.read());(ROOT/'busy-first.stderr').write_text(first.stderr.read())
case('busy',busy)
def storage():
 p=base('storagefull');q=dict(path=str(p),op='admit',captures=cs,request=X['events']['A1']['request']['utf8']);env=os.environ.copy();env['VORDA_NATIVE_PAGE_LIMIT']='current'
 r=subprocess.run([BIN],input=C(q),capture_output=True,text=True,env=env);(ROOT/'storage-full.stdout').write_text(r.stdout);(ROOT/'storage-full.stderr').write_text(r.stderr);v=json.loads(r.stdout);assert v.get('status')==503,v
 db=sqlite3.connect(p);assert db.execute('select count(*) from v2_deliveries').fetchone()[0]==0;assert db.execute('select count(*) from v2_authorities').fetchone()[0]==0;db.close()
case('storage-full',storage)
# V1 drain uses its unchanged production HTTP client against a one-shot loopback fixture.
def legacy(good):
 import http.server,threading
 hub=base('v1-hub-good' if good else 'v1-hub-bad');submit(hub,'A1');original_view=view(hub);p=ROOT/('legacygood.db' if good else 'legacybad.db');db=sqlite3.connect(p);db.executescript(X['outbox_ddl']);db.execute('pragma user_version=1');db.execute('insert into identity values(?,?,?)',X['legacy']['identity_row']);db.execute('insert into pending values(?,?,?,?)',(7,X['legacy']['queue']['utf8'].encode(),2,0));db.commit();db.close()
 class Handler(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
   raw=self.rfile.read(int(self.headers['Content-Length']));assert raw==X['legacy']['queue']['utf8'].encode();ack=X['legacy']['good_ack' if good else 'bad_ack']['utf8'].encode();self.send_response(200);self.send_header('Content-Length',str(len(ack)));self.end_headers();self.wfile.write(ack)
  def log_message(self,*_args):pass
 server=http.server.HTTPServer(('127.0.0.1',0),Handler);t=threading.Thread(target=server.handle_request);t.start();r=call(p,'v1-drain',url='http://127.0.0.1:'+str(server.server_port));t.join(5);server.server_close();assert r=={'ok':good},r
 db=sqlite3.connect(p);rows=db.execute('select payload,attempts,due from pending').fetchall()
 if good:
  assert not rows;batch=json.loads(X['legacy']['queue']['utf8']);batch['scan']='00000000-0000-4000-8000-000000000008';assert call(p,'v1-enqueue',batch=batch)['ok']['sequence']==8
 else:assert rows[0][0]==X['legacy']['queue']['utf8'].encode() and rows[0][1]==3 and time.time()<rows[0][2]<=time.time()+9
 db.close();assert view(hub)==original_view
case('v1-good-ack-after-v2',lambda:legacy(True));case('v1-bad-ack-refusal',lambda:legacy(False))
def attempt():
 root=ROOT/'app';root.mkdir();state=ROOT/'native-state';request=ROOT/'capture-request.json';binary=str((pathlib.Path(BIN).resolve().parent.parent if pathlib.Path(BIN).parent.name=='examples' else pathlib.Path(BIN).resolve().parent)/'vorda')
 def cap(q):
  request.write_text(C(q));r=subprocess.run([binary,'--state',str(state),'capture',str(request)],capture_output=True,text=True);n=len(list(ROOT.glob('native-*.request.json')));(ROOT/('native-%d.request.json'%n)).write_text(C(q));(ROOT/('native-%d.stdout'%n)).write_text(r.stdout);(ROOT/('native-%d.stderr'%n)).write_text(r.stderr);return r
 for i in json.loads(X['events']['A1']['artifact']['utf8'])['inputs']:
  p=root/i['path'];p.parent.mkdir();p.write_text(i['bytes_utf8'])
 q=dict(X['native_attempt']['request']);q['root']=str(root);q['token']='native-before';q.pop('provider');q['observed_at']='1793898285.4219873';q['completed_at']='1793898285.5764945';r=cap(q);assert r.returncode==0,r.stderr;initial=json.loads(r.stdout);assert initial['revision']==1;export=ROOT/'native-s1.json';r=subprocess.run([binary,'--state',str(state),'capture-export',initial['snapshot_id'],str(export)],capture_output=True,text=True);assert r.returncode==0;rbytes=export.read_bytes()
 # Freeze the unsuccessful native-after inputs from the accepted semantic fixture.
 for i in X['native_attempt']['attempt_outcome']['inputs']:
  (root/i['path']).write_text(i['bytes_utf8'])
 q=dict(X['native_attempt']['request']);q['root']=str(root);r=cap(q);assert r.returncode==0,r.stderr;out=json.loads(r.stdout);assert out['status']=='unsuccessful' and out['revision'] is None
 r=subprocess.run([binary,'--state',str(state),'capture-attempt','native-after'],capture_output=True,text=True);assert r.returncode==0 and json.loads(r.stdout)==out
 assert out['current_retained']==initial['snapshot_id'];assert json.loads(cap(q).stdout)==out;r=subprocess.run([binary,'--state',str(state),'capture-export',initial['snapshot_id'],str(export)],capture_output=True,text=True);assert r.returncode==0 and export.read_bytes()==rbytes;q['completed_at']='1793898300.6';assert 'capture_token_conflict' in cap(q).stderr
 q['token']='valid-next';q['inputs']=['a/package-lock.json'];q.pop('provider');assert json.loads(cap(q).stdout)['revision']==2
case('native-attempt-token-operations',attempt)
# Security controls beyond the 35 frozen cases.
def digest_control():
 p=base('digestcontrol');q=json.loads(X['events']['A1']['request']['utf8']);q['artifact_sha256']='0'*64;assert call(p,'admit',request=C(q)).get('status')==422
case('control-altered-digest',digest_control)
def escaped_duplicate():
 p=base('decodedduplicate');q=json.loads(X['events']['A1']['request']['utf8']);raw=q['artifact_utf8'];raw='{"revision":1,"revis\\u0069on":1,'+raw[1:];q['artifact_utf8']=raw;q['artifact_byte_length']=len(raw.encode());q['artifact_sha256']=hashlib.sha256(raw.encode()).hexdigest();trusted=[dict(c,artifact_utf8=raw) if c['evidence_id']==q['evidence_id'] and c['binding']==q['binding'] else c for c in cs];assert call(p,'admit',request=C(q),captures=trusted).get('status')==400
case('control-decoded-duplicate',escaped_duplicate)
print(json.dumps(results,indent=2));sys.exit(any(r['result']=='FAIL' for r in results))
