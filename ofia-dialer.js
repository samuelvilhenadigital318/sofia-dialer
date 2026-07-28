/**
 * Sofia SIP Dialer v3 — SuperCotação / Grupo Sandri
 * 
 * Quando o lead atende, faz REFER para transferir direto para o ramal da Maria
 * sem desligar a chamada original.
 */

'use strict';

const crypto = require('crypto');
const tls    = require('tls');

const CONFIG = {
  user:          '146482001',
  password:      'c5dabea1',
  host:          'app.nvoip.com.br',
  port:          7443,
  realm:         'app.nvoip.com.br',
  callerId:      '+554720190290',
  destination:   process.argv[2] || null,
  ramalMaria:    process.argv[3] || '146482001',
  answerTimeout: parseInt(process.argv[4] || '25', 10),
};

if (!CONFIG.destination) {
  process.stdout.write(JSON.stringify({ status: 'error', message: 'Numero nao informado' }) + '\n');
  process.exit(1);
}

function output(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }
function log(msg)    { process.stderr.write('[Sofia v3] ' + msg + '\n'); }
function md5(s)      { return crypto.createHash('md5').update(s).digest('hex'); }

function generateCallId()  { return crypto.randomBytes(12).toString('hex') + '@' + CONFIG.host; }
function generateTag()     { return crypto.randomBytes(8).toString('hex'); }
function generateBranch()  { return 'z9hG4bK' + crypto.randomBytes(8).toString('hex'); }

function computeDigest({ username, password, realm, method, uri, nonce, nc, cnonce, qop }) {
  const ha1 = md5(username + ':' + realm + ':' + password);
  const ha2 = md5(method + ':' + uri);
  if (qop) return md5(ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2);
  return md5(ha1 + ':' + nonce + ':' + ha2);
}

function parseWWWAuth(header) {
  const result = {};
  [['realm', /realm="([^"]+)"/], ['nonce', /nonce="([^"]+)"/],
   ['qop', /qop="([^"]+)"/], ['algorithm', /algorithm=([^\s,]+)/],
   ['opaque', /opaque="([^"]+)"/]].forEach(([k, re]) => {
    const m = header.match(re); if (m) result[k] = m[1];
  });
  return result;
}

let cseq = 1, callId = generateCallId(), localTag = generateTag(), branch = generateBranch();
let callAnswered = false, answerTimer = null;
let callStartTime = null;

class SIPWebSocket {
  constructor(host, port) {
    this.host = host; this.port = port; this.socket = null;
    this._wsKey = crypto.randomBytes(16).toString('base64');
    this._upgraded = false; this._frameBuffer = Buffer.alloc(0);
    this._httpBuffer = '';
    this.onmessage = null; this.onopen = null; this.onclose = null; this.onerror = null;
  }

  connect() {
    log('Conectando ' + this.host + ':' + this.port);
    this.socket = tls.connect({
      host: this.host, port: this.port,
      rejectUnauthorized: false, servername: this.host,
    });
    this.socket.on('secureConnect', () => {
      log('TLS OK');
      this.socket.write([
        'GET / HTTP/1.1',
        'Host: ' + this.host + ':' + this.port,
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: ' + this._wsKey,
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Protocol: sip',
        'Origin: https://' + this.host,
        '\r\n',
      ].join('\r\n'));
    });
    this.socket.on('data', (data) => {
      if (!this._upgraded) {
        this._httpBuffer += data.toString('binary');
        const end = this._httpBuffer.indexOf('\r\n\r\n');
        if (end === -1) return;
        const header = this._httpBuffer.substring(0, end);
        const rest = this._httpBuffer.substring(end + 4);
        if (header.includes('101 Switching')) {
          log('WS OK');
          this._upgraded = true;
          if (rest.length > 0) {
            this._frameBuffer = Buffer.concat([this._frameBuffer, Buffer.from(rest, 'binary')]);
            this._processFrames();
          }
          if (this.onopen) this.onopen();
        } else {
          if (this.onerror) this.onerror(new Error('WS falhou: ' + header.substring(0, 80)));
        }
        return;
      }
      this._frameBuffer = Buffer.concat([this._frameBuffer, data]);
      this._processFrames();
    });
    this.socket.on('error', e => { if (this.onerror) this.onerror(e); });
    this.socket.on('close', () => { if (this.onclose) this.onclose(); });
  }

  _processFrames() {
    while (this._frameBuffer.length >= 2) {
      const b0 = this._frameBuffer[0], b1 = this._frameBuffer[1];
      const op = b0 & 0xF, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7F, off = 2;
      if (len === 126) { if (this._frameBuffer.length < 4) break; len = this._frameBuffer.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this._frameBuffer.length < 10) break; len = Number(this._frameBuffer.readBigUInt64BE(2)); off = 10; }
      const ml = masked ? 4 : 0;
      if (this._frameBuffer.length < off + ml + len) break;
      let payload;
      if (masked) {
        const m = this._frameBuffer.slice(off, off+4); off += 4;
        payload = Buffer.alloc(len);
        for (let i = 0; i < len; i++) payload[i] = this._frameBuffer[off+i] ^ m[i%4];
      } else payload = this._frameBuffer.slice(off, off+len);
      this._frameBuffer = this._frameBuffer.slice(off+len);
      if (op === 1 || op === 0) { if (this.onmessage) this.onmessage(payload.toString('utf8')); }
      else if (op === 8) { log('Close frame'); if (this.onclose) this.onclose(); }
      else if (op === 9) { this.socket.write(Buffer.from([0x8A, 0x00])); }
    }
  }

  send(text) {
    if (!this.socket || !this._upgraded) return;
    const p = Buffer.from(text, 'utf8'), l = p.length, m = crypto.randomBytes(4);
    let h;
    if (l < 126) { h = Buffer.alloc(6); h[0]=0x81; h[1]=0x80|l; m.copy(h,2); }
    else { h = Buffer.alloc(8); h[0]=0x81; h[1]=0x80|126; h.writeUInt16BE(l,2); m.copy(h,4); }
    const ms = Buffer.alloc(l);
    for (let i=0; i<l; i++) ms[i]=p[i]^m[i%4];
    this.socket.write(Buffer.concat([h,ms]));
  }

  close() { try { this.socket.write(Buffer.from([0x88,0x00])); this.socket.destroy(); } catch(_){} }
}

function buildREG(auth='') {
  const lines = [
    'REGISTER sip:' + CONFIG.host + ' SIP/2.0',
    'Via: SIP/2.0/WSS ' + CONFIG.host + ';branch=' + branch + ';rport',
    'Max-Forwards: 70',
    'From: <sip:' + CONFIG.user + '@' + CONFIG.host + '>;tag=' + localTag,
    'To: <sip:' + CONFIG.user + '@' + CONFIG.host + '>',
    'Call-ID: ' + callId,
    'CSeq: ' + cseq + ' REGISTER',
    'Contact: <sip:' + CONFIG.user + '@' + CONFIG.host + ';transport=wss>',
    'Expires: 60',
    'User-Agent: Sofia-SDR/1.0',
    'Content-Length: 0',
  ];
  if (auth) lines.splice(7, 0, auth);
  return lines.join('\r\n') + '\r\n\r\n';
}

function buildINVITE(dest, sdp, auth='') {
  const dn = dest.replace(/\D/g,'');
  const toUri = 'sip:' + dn + '@' + CONFIG.host;
  branch = generateBranch();
  const lines = [
    'INVITE ' + toUri + ' SIP/2.0',
    'Via: SIP/2.0/WSS ' + CONFIG.host + ';branch=' + branch + ';rport',
    'Max-Forwards: 70',
    'From: <sip:' + CONFIG.user + '@' + CONFIG.host + '>;tag=' + localTag,
    'To: <' + toUri + '>',
    'Call-ID: ' + callId,
    'CSeq: ' + cseq + ' INVITE',
    'Contact: <sip:' + CONFIG.user + '@' + CONFIG.host + ';transport=wss>',
    'Content-Type: application/sdp',
    'User-Agent: Sofia-SDR/1.0',
    'Content-Length: ' + Buffer.byteLength(sdp),
  ];
  if (auth) lines.splice(9, 0, auth);
  return lines.join('\r\n') + '\r\n\r\n' + sdp;
}

function buildREFER(toHeader, toTag, referTo) {
  // REFER transfere a chamada para o ramal da Maria
  const dn = CONFIG.destination.replace(/\D/g,'');
  const br = generateBranch();
  cseq++;
  return [
    'REFER sip:' + dn + '@' + CONFIG.host + ' SIP/2.0',
    'Via: SIP/2.0/WSS ' + CONFIG.host + ';branch=' + br,
    'Max-Forwards: 70',
    'From: <sip:' + CONFIG.user + '@' + CONFIG.host + '>;tag=' + localTag,
    'To: ' + toHeader + (toTag ? ';tag=' + toTag : ''),
    'Call-ID: ' + callId,
    'CSeq: ' + cseq + ' REFER',
    'Refer-To: <sip:' + referTo + '@' + CONFIG.host + '>',
    'Referred-By: <sip:' + CONFIG.user + '@' + CONFIG.host + '>',
    'Content-Length: 0',
  ].join('\r\n') + '\r\n\r\n';
}

function buildSDP() {
  const id = Date.now();
  return 'v=0\r\no=sofia ' + id + ' ' + id + ' IN IP4 ' + CONFIG.host + '\r\ns=Sofia SDR\r\nc=IN IP4 ' + CONFIG.host + '\r\nt=0 0\r\nm=audio 9 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n';
}

function parseSIP(msg) {
  const lines = msg.split('\r\n');
  const r = { headers: {}, body: '', raw: msg };
  const sm = lines[0].match(/SIP\/2\.0 (\d+) (.*)/);
  const rm = lines[0].match(/^(\w+) (sip:[^\s]+) SIP\/2\.0/);
  if (sm) { r.type='response'; r.code=parseInt(sm[1],10); r.reason=sm[2]; }
  else if (rm) { r.type='request'; r.method=rm[1]; }
  let bStart=false;
  for (let i=1; i<lines.length; i++) {
    if (lines[i]==='') { bStart=true; continue; }
    if (bStart) { r.body+=lines[i]+'\r\n'; continue; }
    const c=lines[i].indexOf(':');
    if (c>0) r.headers[lines[i].substring(0,c).trim().toLowerCase()]=lines[i].substring(c+1).trim();
  }
  return r;
}

let ws, state='idle', toHeader='', toTag='';

function onSIPMessage(raw) {
  log('<< ' + raw.split('\r\n')[0]);
  const msg = parseSIP(raw);

  if (state === 'registering') {
    if (msg.code === 401) {
      const a = parseWWWAuth(msg.headers['www-authenticate']||'');
      const nc='00000001', cn=crypto.randomBytes(4).toString('hex');
      const resp = computeDigest({
        username:CONFIG.user, password:CONFIG.password,
        realm:a.realm||CONFIG.realm, method:'REGISTER',
        uri:'sip:'+CONFIG.host, nonce:a.nonce, nc, cnonce:cn, qop:a.qop?'auth':null
      });
      let ah='Authorization: Digest username="'+CONFIG.user+'",realm="'+(a.realm||CONFIG.realm)+'",nonce="'+a.nonce+'",uri="sip:'+CONFIG.host+'",response="'+resp+'"';
      if (a.qop) ah+=',qop=auth,nc='+nc+',cnonce="'+cn+'"';
      if (a.algorithm) ah+=',algorithm='+a.algorithm;
      if (a.opaque) ah+=',opaque="'+a.opaque+'"';
      cseq++; branch=generateBranch();
      ws.send(buildREG(ah)); return;
    }
    if (msg.code === 200) { log('Registrado!'); state='registered'; doInvite(); return; }
    if (msg.code >= 400) return finish('error', 'REGISTER falhou: '+msg.code);
  }

  if (state === 'calling') {
    if (msg.type==='response') {
      if (msg.code>=100 && msg.code<200) {
        log('Provisional: '+msg.code);
        if (msg.code === 183 || msg.code === 180) callStartTime = Date.now();
        return;
      }
      if (msg.code===200) {
        const tf=msg.headers['to']||'';
        const tm=tf.match(/;tag=([^\s;]+)/);
        toTag=tm?tm[1]:''; toHeader=tf.split(';tag=')[0];
        // tempo medido desde o 183 (já definido antes)
        clearTimeout(answerTimer); callAnswered=true;
        log('ATENDIDA! Enviando ACK...');

        // ACK
        const dn=CONFIG.destination.replace(/\D/g,'');
        const br=generateBranch();
        ws.send('ACK sip:'+dn+'@'+CONFIG.host+' SIP/2.0\r\nVia: SIP/2.0/WSS '+CONFIG.host+';branch='+br+'\r\nMax-Forwards: 70\r\nFrom: <sip:'+CONFIG.user+'@'+CONFIG.host+'>;tag='+localTag+'\r\nTo: '+toHeader+(toTag?';tag='+toTag:'')+'\r\nCall-ID: '+callId+'\r\nCSeq: '+cseq+' ACK\r\nContent-Length: 0\r\n\r\n');
        state='answered';

        // Calcular tempo de atendimento
        const tempoAtendimento = callStartTime ? (Date.now() - callStartTime) / 1000 : 999;
        const caixaPostal = tempoAtendimento < 8;

        output({
          status: caixaPostal ? 'caixa_postal' : 'answered',
          callId, destination: CONFIG.destination,
          tempoAtendimento: Math.round(tempoAtendimento)
        });

        if (!caixaPostal) {
          // Transferir para Maria via REFER
          log('Transferindo para Maria via REFER...');
          setTimeout(() => {
            ws.send(buildREFER(toHeader, toTag, CONFIG.ramalMaria));
          }, 500);

          // Aguardar NOTIFY de sucesso ou timeout de 10s
          setTimeout(() => {
            log('Encerrando apos transferencia...');
            ws.close();
            process.exit(0);
          }, 10000);
        } else {
          // Caixa postal - desligar
          log('Caixa postal detectada, desligando...');
          cseq++;
          const bb=generateBranch();
          ws.send('BYE sip:'+dn+'@'+CONFIG.host+' SIP/2.0\r\nVia: SIP/2.0/WSS '+CONFIG.host+';branch='+bb+'\r\nMax-Forwards: 70\r\nFrom: <sip:'+CONFIG.user+'@'+CONFIG.host+'>;tag='+localTag+'\r\nTo: '+toHeader+(toTag?';tag='+toTag:'')+'\r\nCall-ID: '+callId+'\r\nCSeq: '+cseq+' BYE\r\nContent-Length: 0\r\n\r\n');
          setTimeout(() => { ws.close(); process.exit(0); }, 2000);
        }
        return;
      }
      if (msg.code===401||msg.code===407) {
        const ahn=msg.code===407?'proxy-authenticate':'www-authenticate';
        const a=parseWWWAuth(msg.headers[ahn]||'');
        const nc='00000001', cn=crypto.randomBytes(4).toString('hex');
        const dn=CONFIG.destination.replace(/\D/g,'');
        const resp=computeDigest({
          username:CONFIG.user, password:CONFIG.password,
          realm:a.realm||CONFIG.realm, method:'INVITE',
          uri:'sip:'+dn+'@'+CONFIG.host, nonce:a.nonce, nc, cnonce:cn, qop:a.qop?'auth':null
        });
        const prefix=msg.code===407?'Proxy-Authorization':'Authorization';
        let ah=prefix+': Digest username="'+CONFIG.user+'",realm="'+(a.realm||CONFIG.realm)+'",nonce="'+a.nonce+'",uri="sip:'+dn+'@'+CONFIG.host+'",response="'+resp+'"';
        if (a.qop) ah+=',qop=auth,nc='+nc+',cnonce="'+cn+'"';
        if (a.algorithm) ah+=',algorithm='+a.algorithm;
        if (a.opaque) ah+=',opaque="'+a.opaque+'"';
        cseq++; branch=generateBranch();
        ws.send(buildINVITE(CONFIG.destination, buildSDP(), ah)); return;
      }
      if (msg.code>=400) return finish(
        msg.code===486||msg.code===603?'busy':
        msg.code===404||msg.code===484?'invalid_number':'rejected',
        'Codigo: '+msg.code
      );
    }
    if (msg.type==='request'&&msg.method==='BYE') {
      clearTimeout(answerTimer);
      return finish('no_answer', 'Cancelado pelo servidor');
    }
  }

  if (state==='answered') {
    if (msg.type==='request'&&msg.method==='BYE') { ws.close(); process.exit(0); }
    // NOTIFY de sucesso do REFER
    if (msg.type==='request'&&msg.method==='NOTIFY') {
      log('NOTIFY recebido — transferencia em andamento');
      // Responder 200 OK ao NOTIFY
      const br=generateBranch();
      ws.send('SIP/2.0 200 OK\r\nVia: '+msg.headers['via']+'\r\nFrom: '+msg.headers['from']+'\r\nTo: '+msg.headers['to']+'\r\nCall-ID: '+msg.headers['call-id']+'\r\nCSeq: '+msg.headers['cseq']+'\r\nContent-Length: 0\r\n\r\n');
    }
  }
}

function doInvite() {
  state='calling'; callId=generateCallId(); cseq=1;
  branch=generateBranch(); localTag=generateTag();
  log('INVITE => ' + CONFIG.destination);
  ws.send(buildINVITE(CONFIG.destination, buildSDP()));
  answerTimer=setTimeout(() => {
    if (!callAnswered) finish('no_answer', 'Sem resposta em '+CONFIG.answerTimeout+'s');
  }, CONFIG.answerTimeout*1000);
}

function finish(status, message) {
  clearTimeout(answerTimer);
  output(Object.assign({status, callId, destination:CONFIG.destination}, message?{message}:{}));
  try { ws.close(); } catch(_) {}
  process.exit(0);
}

log('Sofia v3 — ' + CONFIG.destination + ' | Maria: ' + CONFIG.ramalMaria);
ws = new SIPWebSocket(CONFIG.host, CONFIG.port);
ws.onopen    = () => { state='registering'; ws.send(buildREG()); };
ws.onmessage = (msg) => onSIPMessage(msg);
ws.onerror   = (e) => finish('error', e.message);
ws.onclose   = () => { if (state!=='answered'&&!callAnswered) finish('error','Conexao fechada'); };
ws.connect();
setTimeout(() => finish('error','Timeout global'), (CONFIG.answerTimeout+15)*1000);
