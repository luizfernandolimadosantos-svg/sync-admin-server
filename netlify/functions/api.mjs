import {getStore} from '@netlify/blobs';
import {createHash, timingSafeEqual} from 'node:crypto';

const json=(status,data)=>({statusCode:status,headers:{
  'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
  'X-Content-Type-Options':'nosniff'},body:JSON.stringify(data)});
const validId=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const validToken=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const hash=x=>createHash('sha256').update(x).digest('hex');
const equal=(a,b)=>{
  if(typeof a!=='string'||typeof b!=='string')return false;
  const x=Buffer.from(a),y=Buffer.from(b);
  return x.length===y.length&&timingSafeEqual(x,y);
};
const store=()=>getStore({name:'sync-devices',consistency:'strong'});
const key=id=>'device-'+id;
const isAdmin=event=>{
  const secret=process.env.SYNC_ADMIN_TOKEN;
  const auth=event.headers?.authorization||event.headers?.Authorization||'';
  return !!secret&&secret.length>=32&&equal(auth,`Bearer ${secret}`);
};
export const handler=async event=>{
  try{
    const route=(event.path||'').split('/').filter(Boolean).pop();
    const method=event.httpMethod;
    if(method==='OPTIONS')return json(405,{error:'Not allowed'});
    if(method!=='POST')return json(405,{error:'POST required'});
    if((event.body||'').length>50000)return json(413,{error:'Payload too large'});
    let body={};
    try{body=JSON.parse(event.body||'{}')}catch{return json(400,{error:'Invalid JSON'})}
    const db=store();
    if(route==='hello'||route==='report'){
      const {device,token}=body;
      if(!validId(device)||!validToken(token))return json(400,{error:'Invalid device or token'});
      let record=await db.get(key(device),{type:'json'});
      const tokenHash=hash(token);
      if(record&&!equal(record.tokenHash,tokenHash))
        return json(403,{error:'Device credential mismatch'});
      const now=Date.now();
      if(!record)record={device,tokenHash,status:'pending',firstSeen:now,lastSeen:now,report:null};
      record.lastSeen=now;
      if(route==='report'){
        if(body.consent!==true||typeof body.report!=='string'||body.report.length>36000)
          return json(400,{error:'Explicit consent required; max 36000 chars'});
        record.report=body.report;
        record.reportAt=now;
      }
      await db.setJSON(key(device),record);
      return json(200,{status:record.status,reportReceived:route==='report'});
    }
    if(!isAdmin(event))return json(401,{error:'Admin authentication required'});
    if(route==='list'){
      const result=await db.list({prefix:'device-',paginate:false});
      const records=[];
      for(const blob of result.blobs||[]){
        const item=await db.get(blob.key,{type:'json'});
        if(item)records.push({device:item.device,status:item.status,
          firstSeen:item.firstSeen,lastSeen:item.lastSeen,
          hasReport:typeof item.report==='string',reportAt:item.reportAt||null});
      }
      records.sort((a,b)=>b.lastSeen-a.lastSeen);
      return json(200,{devices:records.slice(0,500)});
    }
    if(route==='decision'){
      if(!validId(body.device)||!['locked','unlocked'].includes(body.status))
        return json(400,{error:'Invalid decision'});
      const record=await db.get(key(body.device),{type:'json'});
      if(!record)return json(404,{error:'Unknown device'});
      record.status=body.status;
      await db.setJSON(key(body.device),record);
      return json(200,{ok:true,status:record.status});
    }
    if(route==='view'){
      if(!validId(body.device))return json(400,{error:'Invalid device'});
      const record=await db.get(key(body.device),{type:'json'});
      if(!record)return json(404,{error:'Unknown device'});
      return json(200,{report:record.report||'',reportAt:record.reportAt||null});
    }
    return json(404,{error:'Unknown route'});
  }catch(error){
    console.error('SYNC API failure',error?.message);
    return json(500,{error:'Server error'});
  }
};
