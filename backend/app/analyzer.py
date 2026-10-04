import re, hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

TERMS={'urgent':10,'immediately':8,'verify your account':14,'password':6,'suspended':12,'blocked':12,'click here':9,'confirm your identity':12,'payment failed':10,'security alert':8,'login':5,'gift card':8,'wire transfer':12}
BRANDS=['paypal','google','microsoft','apple','amazon','netflix','sbi','hdfc','icici','upi','bank']

def parse(data): return BytesParser(policy=policy.default).parsebytes(data)
def body(msg):
    if msg.is_multipart():
        return '\n'.join(p.get_content() for p in msg.walk() if p.get_content_type()=='text/plain')
    try:return msg.get_content()
    except:return ''
def auth(msg):
    s=' '.join(msg.get_all('Authentication-Results',[])).lower(); out={}
    for k in ['spf','dkim','dmarc']:
        m=re.search(rf'\b{k}=(pass|fail|softfail|neutral|none)\b',s);out[k]=m.group(1) if m else 'not_found'
    return out
def geo(ip):
    if ip.startswith(('10.','127.','192.168.','172.16.')): return {'country':'Private/Local','city':'Internal Network','isp':'Private'}
    return {'country':['India','Singapore','Germany','United States','Netherlands'][int(ip.split('.')[0])%5],'city':'Demo enrichment city','isp':'Demo/lookup required'}

def analyze_email(data,filename):
    msg=parse(data); b=body(msg); subject=str(msg.get('Subject','')); sender=str(msg.get('From','')); reply=str(msg.get('Reply-To','')); ret=str(msg.get('Return-Path','')); received=[str(x) for x in msg.get_all('Received',[])]
    text=(subject+'\n'+b).lower();score=0;findings=[]
    for term,pts in TERMS.items():
        if term in text: score+=pts;findings.append({'type':'Content','severity':'Medium','message':f"Suspicious language: '{term}'"})
    au=auth(msg)
    for k,v in au.items():
        if v=='fail':score+=18;findings.append({'type':'Authentication','severity':'Critical','message':f'{k.upper()} authentication failed'})
    sd=parseaddr(sender)[1].lower();rd=parseaddr(reply)[1].lower()
    if sd and rd and sd.split('@')[-1]!=rd.split('@')[-1]:score+=18;findings.append({'type':'Identity','severity':'Critical','message':'From and Reply-To domains do not match'})
    urls=sorted(set(re.findall(r'https?://[^\s<>"\']+',b,re.I)));ips=sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','\n'.join(received)+'\n'+b)))
    domains=sorted(set((urlparse(u).hostname or '') for u in urls if urlparse(u).hostname))
    for d in domains:
        base=d.split('.')[0].lower()
        if any(x in base and base!=x and len(base)<=len(x)+4 for x in BRANDS):score+=20;findings.append({'type':'Impersonation','severity':'Critical','message':f'Possible brand impersonation: {d}'})
    if urls:score+=min(20,len(urls)*5);findings.append({'type':'URL','severity':'High','message':f'{len(urls)} URL indicator(s) extracted'})
    attachments=[]
    for p in msg.walk():
        if p.get_content_disposition()=='attachment':
            raw=p.get_payload(decode=True) or b'';attachments.append({'name':p.get_filename() or 'unnamed','type':p.get_content_type(),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    if attachments:score+=8;findings.append({'type':'Attachment','severity':'High','message':f'{len(attachments)} attachment(s) hashed with SHA-256'})
    score=min(100,score);level='Critical' if score>=80 else 'High' if score>=60 else 'Medium' if score>=30 else 'Low'; verdict='Phishing / Suspicious' if score>=45 else 'Likely Legitimate';confidence=min(.99,max(.55,.55+score/225))
    iocs=[{'type':'IP','value':x} for x in ips]+[{'type':'DOMAIN','value':x} for x in domains]+[{'type':'URL','value':x} for x in urls]+[{'type':'HASH','value':x['sha256']} for x in attachments]
    nodes=[{'id':'email','label':'Email','kind':'email'}];edges=[]
    for i,d in enumerate(domains[:10]):nodes.append({'id':f'd{i}','label':d,'kind':'domain'});edges.append(['email',f'd{i}'])
    for i,ip in enumerate(ips[:10]):nodes.append({'id':f'i{i}','label':ip,'kind':'ip'});edges.append(['email',f'i{i}'])
    for i,u in enumerate(urls[:10]):nodes.append({'id':f'u{i}','label':u,'kind':'url'});edges.append(['email',f'u{i}'])
    return {'case_id':f'CASE-{abs(hash(data))%1000000:06d}','filename':filename,'classification':verdict,'severity':level,'risk_score':score,'ml':{'label':verdict,'confidence':round(confidence,2),'model':'Explainable phishing baseline'},'sender':sender,'reply_to':reply,'return_path':ret,'subject':subject,'authentication':au,'received_count':len(received),'received_headers':received,'ips':ips,'urls':urls,'domains':domains,'findings':findings,'attachments':attachments,'iocs':iocs,'geo':[{'ip':ip,**geo(ip)} for ip in ips],'graph':{'nodes':nodes,'edges':edges},'recommendation':'Quarantine and investigate; validate sender independently.' if score>=45 else 'No strong phishing indicators detected.'}
