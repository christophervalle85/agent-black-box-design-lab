/**
 * Protocol contract for the EXPERIMENTAL (non-MCP) Node-to-native notes host.
 * Synthetic names only. Does not confer gateway audit or approval authority.
 */
const TEST_NAME=/^bbx-test-[A-Za-z0-9_-]{1,51}\.txt$/;
const allowed=new Set(['READ','WRITE','REMOVE']);

export function frameBridgeRequest(method,path,content='') {
  if(!allowed.has(method))throw Error('Unsupported native bridge method.');
  if(typeof path!=='string'||path.length>64||!TEST_NAME.test(path))
    throw Error('Native bridge only accepts bounded synthetic filenames.');
  if(typeof content!=='string')throw Error('Native bridge content must be text.');
  if(method!=='WRITE'&&content!=='')throw Error('Only WRITE may carry note content.');
  const bytes=Buffer.from(content,'utf8');
  if(method==='WRITE'&&(bytes.length<1||bytes.length>2000||
      !/^[\x09\x0a\x20-\x7e]+$/.test(content)))
    throw Error('Native bridge note content must be 1-2000 safe ASCII bytes.');
  return Buffer.concat([Buffer.from([method,path,bytes.length].join(' ')+'\n','ascii'),bytes]);
}

/**
 * Decode fixed-size native replies, rejecting trailing bytes, insufficient
 * payloads, unexpected status tokens and oversized response bodies.
 */
export function parseBridgeReplies(bytes,count) {
  if(!Buffer.isBuffer(bytes)||!Number.isSafeInteger(count)||count<1||count>8)
    throw Error('Invalid native bridge reply collection.');
  const result=[];
  let offset=0;
  for(let i=0;i<count;i++){
    const end=bytes.indexOf(10,offset);
    if(end<0||end-offset<1||end-offset>16)throw Error('Missing or oversized native reply header.');
    const header=bytes.subarray(offset,end).toString('ascii');
    const match=/^(OK|ERR) (0|[1-9][0-9]{0,3})$/.exec(header);
    if(!match)throw Error('Invalid native reply header.');
    const length=Number(match[2]);
    if(length>2000||match[1]==='ERR'&&length!==0)throw Error('Invalid native reply length.');
    const start=end+1;
    if(bytes.length-start<length)throw Error('Native reply body truncated.');
    result.push({ok:match[1]==='OK',content:bytes.subarray(start,start+length).toString('utf8')});
    offset=start+length;
  }
  if(offset!==bytes.length)throw Error('Unsolicited native reply bytes.');
  return result;
}
export function parseBridgeReply(bytes) {
  return parseBridgeReplies(bytes,1)[0];
}
