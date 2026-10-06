// Run with NODE_PATH pointing to a linkedom installation.
const {parseHTML}=require('linkedom');
const fs=require('fs'),vm=require('vm'),assert=require('assert');
(async()=>{
 const {window,document}=parseHTML(fs.readFileSync('static/index.html','utf8'));
 document.querySelector('#rain').getContext=()=>({});
 // Linkedom does not implement select.value's browser setter.
 Object.defineProperty(window.HTMLSelectElement.prototype,'value',{get(){return this._value||''},set(v){this._value=v}});
 const q=s=>document.querySelector(s);
 q('#details').showModal=()=>{};q('#statusFilter').value='all';
 let prefs={aliases:{},groups:{}}, prompts=['Servers'], stored={},calls=[];
 let state={running:false,progress:100,subnet:'192.168.0.0/24',devices:[{ip:'192.168.0.2',mac:'AA:BB:CC:11:22:33',name:'host.local',status:'online'}]};
 const fetch=async(url,opt={})=>{
  calls.push([url,opt]); let data={};
  if(url==='/api/preferences'){
   if(opt.body){const b=JSON.parse(opt.body);if(b.kind==='group'){if(b.delete)delete prefs.groups[b.name];else prefs.groups[b.name]=b.ips}else{if(b.name)prefs.aliases[b.mac]=b.name;else delete prefs.aliases[b.mac]}}
   data=prefs;
  }
  if(url==='/api/interfaces')data={interfaces:[],default:''};
  if(url==='/api/scan')data=state;
  if(url==='/api/watch')data={results:JSON.parse(opt.body).ips.map(ip=>({ip,online:true,latency_ms:1,checked_at:Date.now()}))};
  if(url.startsWith('/api/details'))data={latency:1,os:[],ports:[]};
  return {ok:true,json:async()=>structuredClone(data)};
 };
 const ctx=vm.createContext({document,window,fetch,console,Date,Map,Set,URL,AbortController,location:{href:'http://localhost/'},localStorage:{getItem:k=>stored[k]||null,setItem:(k,v)=>stored[k]=v},innerWidth:1000,innerHeight:900,setInterval:()=>1,setTimeout:()=>1,clearTimeout:()=>{},addEventListener:()=>{},prompt:()=>prompts.shift(),confirm:()=>true,alert:()=>{}});
 const run=code=>vm.runInContext(code,ctx),flush=()=>new Promise(r=>setImmediate(r));
 run(fs.readFileSync('static/app.js','utf8'));await flush();
 run("toggleWatch('192.168.0.2',true)");await flush();
 await q('#saveGroup').onclick();assert.deepEqual(prefs.groups.Servers,['192.168.0.2']);
 run('clearWatch()');q('#watchGroup').value='Servers';q('#watchGroup').onchange();await flush();
 assert.equal(run('watched.size'),1);assert(!q('#watchPanel').classList.contains('hidden'));
 await run("details('192.168.0.2')");q('#aliasName').value='Printer <Office>';
 await q('#deviceAlias').onsubmit({preventDefault(){}});
 assert(q('#rows').textContent.includes('Printer <Office>'));assert(!q('#rows').querySelector('office'));
 state={...state,subnet:'192.168.13.0/24',devices:[{ip:'192.168.13.8',mac:'AA:BB:CC:11:22:33',name:'new-host',status:'online'},{ip:'192.168.0.2',mac:'AA:BB:CC:44:55:66',name:'other-device',status:'online'}]};
 await run('poll()');assert.equal(run('watched.size'),1);
 assert.equal(run("devices.find(d=>d.ip==='192.168.13.8').name"),'Printer <Office>');
 assert.equal(run("devices.find(d=>d.ip==='192.168.0.2').name"),'other-device');
 await run("details('192.168.13.8')");q('#aliasName').value='';await q('#deviceAlias').onsubmit({preventDefault(){}});
 assert.equal(run("devices.find(d=>d.ip==='192.168.13.8').name"),'new-host');
 q('#watchGroup').value='Servers';await q('#deleteGroup').onclick();assert.equal(Object.keys(prefs.groups).length,0);assert.equal(run('watched.size'),1);
 console.log('Saved group load/delete, retained selection, escaped alias, MAC identity across IP changes, and hostname restore: OK');
})().catch(e=>{console.error(e);process.exit(1)});
