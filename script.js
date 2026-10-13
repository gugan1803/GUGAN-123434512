const BRANDS={paypal:["paypal.com"],google:["google.com","goo.gl"],microsoft:["microsoft.com","live.com","office.com"],apple:["apple.com","icloud.com"],amazon:["amazon.com","amazon.in"],facebook:["facebook.com","fb.com"],instagram:["instagram.com"],netflix:["netflix.com"],sbi:["sbi.co.in","onlinesbi.sbi"],hdfc:["hdfcbank.com"],icici:["icicibank.com"],paytm:["paytm.com"],whatsapp:["whatsapp.com"],linkedin:["linkedin.com"],dropbox:["dropbox.com"]};
const SHORT=["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly","cutt.ly","rb.gy","shorturl.at"];
const BADTLD=["xyz","top","tk","ml","ga","cf","gq","click","zip","work","support","country","buzz","icu","cam","rest"];
const KW=["login","signin","verify","secure","account","update","banking","confirm","password","wallet","suspend","unlock","kyc","billing","webscr"];
const SLD=["co","com","org","net","gov","ac","edu"];
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function regDomain(host){
  const p=host.split(".");if(p.length<=2)return host;
  const n=p.length;
  if(p[n-1].length===2&&SLD.includes(p[n-2]))return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}
function entropy(s){const m={};for(const c of s)m[c]=(m[c]||0)+1;return -Object.values(m).reduce((a,v)=>a+(v/s.length)*Math.log2(v/s.length),0)}

function analyze(raw){
  raw=raw.trim();
  let u;
  try{u=new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)?raw:"http://"+raw)}catch(e){return null}
  const host=u.hostname.toLowerCase(), full=raw, rd=regDomain(host);
  const labels=host.split("."), tld=labels[labels.length-1];
  const sub=labels.slice(0,labels.length-(rd.split(".").length)).join(".");
  const isIP=/^(\d{1,3}\.){3}\d{1,3}$/.test(host)||host.includes(":");
  const digits=(host.match(/\d/g)||[]).length;
  const f={length:full.length,hostLen:host.length,dots:(host.match(/\./g)||[]).length,subdomains:sub?sub.split(".").length:0,hyphens:(host.match(/-/g)||[]).length,https:u.protocol==="https:",isIP,at:full.includes("@"),port:u.port||"default",digits,entropy:entropy(host).toFixed(2),pathDepth:u.pathname.split("/").filter(Boolean).length,params:[...u.searchParams].length,tld,regDomain:rd};
  const R=[];
  const add=(pts,title,why)=>R.push({pts,title,why});
  if(isIP)add(30,"IP address used as host","Legit sites use domain names. IP hosts are used to hide the real owner.");
  if(f.at)add(25,"'@' symbol in URL","Browsers ignore text before '@', so attackers disguise the real destination.");
  if(!f.https)add(12,"No HTTPS","Connection is unencrypted. (HTTPS alone doesn't mean safe, but missing it is a red flag.)");
  if(f.length>100)add(15,"Very long URL ("+f.length+" chars)","Long URLs hide the malicious part and push the real domain out of view.");
  else if(f.length>75)add(8,"Long URL ("+f.length+" chars)","Above-average length is common in phishing links.");
  if(f.subdomains>=3)add(15,"Too many subdomains ("+f.subdomains+")","Deep subdomain chains like brand.com.evil.xyz imitate trusted names.");
  else if(f.subdomains===2)add(6,"Multiple subdomains","Check which part is actually the registered domain.");
  if(f.hyphens>=2)add(10,"Many hyphens in domain ("+f.hyphens+")","Hyphenated names like 'secure-login-bank' are typical of fake domains.");
  else if(f.hyphens===1&&!isIP)add(3,"Hyphen in domain","Slightly more common in lookalike domains.");
  if(BADTLD.includes(tld))add(15,"Suspicious TLD (.'"+tld+"')","This TLD is cheap/free and heavily abused for throwaway phishing sites.");
  if(SHORT.includes(rd))add(18,"URL shortener","Hides the final destination – expand it before trusting.");
  if(host.startsWith("xn--")||host.includes(".xn--")||/[^\x00-\x7f]/.test(host))add(25,"Punycode / non-ASCII characters","Homograph attack: lookalike Unicode letters mimic a real brand.");
  if(f.port!=="default"&&!["80","443"].includes(f.port))add(10,"Unusual port ("+f.port+")","Legit sites rarely use custom ports in public links.");
  if(digits>=4&&!isIP)add(8,"Many digits in domain ("+digits+")","Random digits suggest auto-generated domains.");
  if(f.entropy>3.6&&host.length>14&&!isIP)add(8,"High-randomness domain (entropy "+f.entropy+")","Looks algorithmically generated.");
  if(full.indexOf("//",8)>-1)add(10,"Extra '//' redirect pattern","Can signal an embedded redirect to another site.");
  if(/%[0-9a-f]{2}/i.test(full))add(6,"Percent-encoded characters","Encoding can be used to obfuscate keywords.");
  const hay=(host+u.pathname+u.search).toLowerCase();
  const hits=KW.filter(k=>hay.includes(k));
  if(hits.length)add(Math.min(5+hits.length*4,20),"Sensitive keywords: "+hits.join(", "),"Phishing pages push urgency/credential words like login, verify, update.");
  for(const [b,legit] of Object.entries(BRANDS)){
    if(hay.includes(b)&&!legit.includes(rd)){add(30,"Brand impersonation: '"+b+"'","Mentions "+b+" but the registered domain is '"+rd+"', not "+legit[0]+".");break}
  }
  const score=Math.min(100,R.reduce((a,r)=>a+r.pts,0));
  R.sort((a,b)=>b.pts-a.pts);
  return{f,R,score,host};
}

function render(a){
  const s=a.score;
  const lvl=s>=50?["PHISHING LIKELY","var(--bad)","Multiple strong indicators – do NOT enter any credentials."]:s>=25?["SUSPICIOUS","var(--warn)","Some risky signals – verify the domain independently before proceeding."]:["LOW RISK","var(--ok)","No major red flags found, but always stay cautious."];
  $("score").textContent=s+"/100";
  $("score").style.color=lvl[1];
  const b=$("badge");b.textContent=lvl[0];b.style.background=lvl[1];
  $("vtext").textContent=lvl[2];
  const bar=$("bar");bar.style.background=lvl[1];bar.style.width="0";requestAnimationFrame(()=>bar.style.width=s+"%");
  $("feats").innerHTML=a.R.length?a.R.map(r=>{
    const c=r.pts>=20?"var(--bad)":r.pts>=10?"var(--warn)":"var(--muted)";
    return `<div class="feat"><div class="dot" style="background:${c}"></div><div><b>${esc(r.title)}</b><span>${esc(r.why)}</span></div><div class="pts" style="color:${c}">+${r.pts}</div></div>`}).join(""):`<div class="feat"><div class="dot" style="background:var(--ok)"></div><div><b>No risk indicators triggered</b><span>URL structure looks normal.</span></div></div>`;
  const f=a.f;
  const rows=[["Registered domain",f.regDomain],["TLD","."+f.tld],["URL length",f.length],["Host length",f.hostLen],["Dots in host",f.dots],["Subdomains",f.subdomains],["Hyphens",f.hyphens],["Digits in host",f.digits],["Host entropy",f.entropy],["HTTPS",f.https?"Yes":"No"],["IP as host",f.isIP?"Yes":"No"],["'@' present",f.at?"Yes":"No"],["Port",f.port],["Path depth",f.pathDepth],["Query params",f.params]];
  $("ft").innerHTML="<tr><th>Feature</th><th>Value</th></tr>"+rows.map(r=>`<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join("");
  $("result").style.display="block";
}
function run(){
  const v=$("url").value;
  if(!v.trim())return;
  const a=analyze(v);
  if(!a){alert("Valid URL illa – check pannunga.");return}
  render(a);
}
$("go").onclick=run;
$("url").addEventListener("keydown",e=>{if(e.key==="Enter")run()});
document.querySelectorAll("[data-u]").forEach(b=>b.onclick=()=>{$("url").value=b.dataset.u;run()});
