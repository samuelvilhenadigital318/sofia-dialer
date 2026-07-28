/**
 * Sofia SIP Dialer v2 — SuperCotação / Grupo Sandri
 * Conecta via WebSocket SIP na Nvoip e disca para um lead.
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
  answerTimeout: parseInt(process.argv[3] || '30', 10),
};

if (!CONFIG.destination) {
  process.stdout.write(JSON.stringify({ status: 'error', message: 'Numero de destino nao informado' }) + '\n');
  process.exit(1);
}

function output(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }
function log(msg)    { process.stderr.write('[Sofia] ' + msg + '\n'); }

function generateCallId()  { return crypto.randomBytes(12).toString('hex') + '@' + CONFIG.host; }
function generateTag()     { return crypto.randomBytes(8).toString('hex'); }
function generateBranch()  { return 'z9hG4bK' + crypto.randomBytes(8).toString('hex'); }
function md5(s)            { return crypto.createHash('md5').update(s).digest('hex'); }

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
    const m = header.match(re);
    if (m) result[k] = m[1];
  });
  return result;
}

let cseq = 1, callId = generateCallId(), localTag = generateTag(), branch = generateBranch();
let callAnswered = false, answerTimer = null;

class SIPWebSocket {
  constructor(host, port) {
    this.host = host; this.port = port; this.socket = null;
    this._wsKey = crypto.randomBytes(16).toString('base64');
    this._upgraded = false; this._frameBuffer = Buffer.alloc(0);
    this._httpBuffer = ''; // buffer para acumular resposta HTTP
    this.onmessage = null; this.onopen = null; this.onclose = null; this.onerror = null;
  }

  connect() {
    log('Conectando em ' + this.host + ':' + this.port);
    this.socket = tls.connect({
      host: this.host, port: this.port,
      rejectUnauthorized: false,
      servername: this.host,
    });

    this.socket.on('secureConnect', () => {
      log('TLS OK. Upgrade WebSocket...');
      const req = [
        'GET / HTTP/1.1',
        'Host: ' + this.host + ':' + this.port,
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: ' + this._wsKey,
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Protocol: sip',
        'Origin: https://' + this.host,
        '\r\n',
      ].join('\r\n');
      this.socket.write(req);
    });

    this.socket.on('data', (data) => {
      if (!this._upgraded) {
        // Acumular dados HTTP até encontrar o fim do header
        this._httpBuffer += data.toString('binary');
        const headerEnd = this._httpBuffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return; // ainda não recebeu o header completo

        const header = this._httpBuffer.substring(0, headerEnd);
        const afterHeader = this._httpBuffer.substring(headerEnd + 4);

        if (header.includes('101 Switching Protocols')) {
          log('WebSocket OK!');
          this._upgraded = true;

          // Se veio dados SIP junto com o 101, processar
          if (afterHeader.length > 0) {
            this._frameBuffer = Buffer.concat([
              this._frameBuffer,
              Buffer.from(afterHeader, 'binary')
            ]);
            this._processFrames();
          }

          if (this.onopen) this.onopen();
        } else {
          if (this.onerror) this.onerror(new Error('WS upgrade falhou: ' + header.substring(0, 100)));
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
      const opcode = b0 & 0x0F;
      const masked  = (b1 & 0x80) !== 0;
      let payloadLen = b1 & 0x7F, offset = 2;

      if (payloadLen === 126) {
        if (this._frameBuffer.length < 4) break;
        payloadLen = this._frameBuffer.readUInt16BE(2); offset = 4;
      } else if (payloadLen === 127) {
        if (this._frameBuffer.length < 10) break;
        payloadLen = Number(this._frameBuffer.readBigUInt64BE(2)); offset = 10;
      }

      const maskLen = masked ? 4 : 0;
      if (this._frameBuffer.length < offset + maskLen + payloadLen) break;

      let payload;
      if (masked) {
        const mask = this._frameBuffer.slice(offset, offset + 4); offset += 4;
        payload = Buffer.alloc(payloadLen);
        for (let i = 0; i < payloadLen; i++) payload[i] = this._frameBuffer[offset + i] ^ mask[i % 4];
      } else {
        payload = this._frameBuffer.slice(offset, offset + payloadLen);
      }

      this._frameBuffer = this._frameBuffer.slice(offset + payloadLen);

      if (opcode === 0x1 || opcode === 0x0) {
        if (this.onmessage) this.onmessage(payload.toString('utf8'));
      } else if (opcode === 0x8) {
        log('Frame close — servidor fechou a conexao');
        if (this.onclose) this.onclose();
      } else if (opcode === 0x9) {
        this.socket.write(Buffer.from([0x8A, 0x00]));
      }
    }
  }

  send(text) {
    if (!this.socket || !this._upgraded) return;
    const payload = Buffer.from(text, 'utf8');
    const len = payload.length;
    const mask = crypto.randomBytes(4);
    let header;
    if (len < 126) {
      header = Buffer.alloc(6); header[0] = 0x81; header[1] = 0x80 | len; mask.copy(header, 2);
    } else {
      header = Buffer.alloc(8); header[0] = 0x81; header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2); mask.copy(header, 4);
    }
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
    this.socket.write(Buffer.concat([header, masked]));
  }

  close() {
    try { this.socket.write(Buffer.from([0x88, 0x00])); this.socket.destroy(); } catch (_) {}
  }
}

function buildREGISTER(auth = '') {
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

function buildINVITE(dest, sdp, auth = '') {
  const dn = dest.replace(/\D/g, '');
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

function buildSDP() {
  const id = Date.now();
  return [
    'v=0',
    'o=sofia ' + id + ' ' + id + ' IN IP4 ' + CONFIG.host,
    's=Sofia SDR',
    'c=IN IP4 ' + CONFIG.host,
    't=0 0',
    'm=audio 9 RTP/AVP 0 8 101',
    'a=rtpmap:0 PCMU/8000',
    'a=rtpmap:8 PCMA/8000',
    'a=rtpmap:101 telephone-event/8000',
    'a=fmtp:101 0-15',
    'a=sendrecv',
    '',
  ].join('\r\n');
}

function parseSIP(msg) {
  const lines = msg.split('\r\n');
  const r = { headers: {}, body: '', raw: msg };
  const sm = lines[0].match(/SIP\/2\.0 (\d+) (.*)/);
  const rm = lines[0].match(/^(\w+) (sip:[^\s]+) SIP\/2\.0/);
  if (sm)      { r.type = 'response'; r.code = parseInt(sm[1], 10); r.reason = sm[2]; }
  else if (rm) { r.type = 'request';  r.method = rm[1]; }
  let bStart = false;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === '') { bStart = true; continue; }
    if (bStart) { r.body += lines[i] + '\r\n'; continue; }
    const c = lines[i].indexOf(':');
    if (c > 0) r.headers[lines[i].substring(0, c).trim().toLowerCase()] = lines[i].substring(c + 1).trim();
  }
  return r;
}

let ws, state = 'idle', toHeader = '', toTag = '';

function onSIPMessage(raw) {
  log('<< ' + raw.split('\r\n')[0]);
  const msg = parseSIP(raw);

  if (state === 'registering') {
    if (msg.code === 401) {
      const a = parseWWWAuth(msg.headers['www-authenticate'] || '');
      const nc = '00000001', cn = crypto.randomBytes(4).toString('hex');
      const resp = computeDigest({
        username: CONFIG.user, password: CONFIG.password,
        realm: a.realm || CONFIG.realm, method: 'REGISTER',
        uri: 'sip:' + CONFIG.host, nonce: a.nonce, nc, cnonce: cn,
        qop: a.qop ? 'auth' : null
      });
      let ah = 'Authorization: Digest username="' + CONFIG.user + '",realm="' + (a.realm || CONFIG.realm) +
               '",nonce="' + a.nonce + '",uri="sip:' + CONFIG.host + '",response="' + resp + '"';
      if (a.qop)       ah += ',qop=auth,nc=' + nc + ',cnonce="' + cn + '"';
      if (a.algorithm) ah += ',algorithm=' + a.algorithm;
      if (a.opaque)    ah += ',opaque="' + a.opaque + '"';
      cseq++; branch = generateBranch();
      log('>> REGISTER (auth)');
      ws.send(buildREGISTER(ah));
      return;
    }
    if (msg.code === 200) { log('Registrado!'); state = 'registered'; doInvite(); return; }
    if (msg.code >= 400) return finish('error', 'REGISTER rejeitado: ' + msg.code);
  }

  if (state === 'calling') {
    if (msg.type === 'response') {
      if (msg.code >= 100 && msg.code < 200) { log('Provisional: ' + msg.code); return; }
      if (msg.code === 200) {
        clearTimeout(answerTimer); callAnswered = true;
        const tf = msg.headers['to'] || '';
        const tm = tf.match(/;tag=([^\s;]+)/);
        toTag = tm ? tm[1] : ''; toHeader = tf.split(';tag=')[0];
        log('ATENDIDA! ACK...');
        const dn = CONFIG.destination.replace(/\D/g, '');
        const br = generateBranch();
        ws.send('ACK sip:' + dn + '@' + CONFIG.host + ' SIP/2.0\r\n' +
          'Via: SIP/2.0/WSS ' + CONFIG.host + ';branch=' + br + '\r\n' +
          'Max-Forwards: 70\r\n' +
          'From: <sip:' + CONFIG.user + '@' + CONFIG.host + '>;tag=' + localTag + '\r\n' +
          'To: ' + toHeader + (toTag ? ';tag=' + toTag : '') + '\r\n' +
          'Call-ID: ' + callId + '\r\n' +
          'CSeq: ' + cseq + ' ACK\r\n' +
          'Content-Length: 0\r\n\r\n');
        state = 'answered';
        output({ status: 'answered', callId, destination: CONFIG.destination, duration: 0 });
        setTimeout(() => {
          cseq++;
          const bb = generateBranch();
          ws.send('BYE sip:' + dn + '@' + CONFIG.host + ' SIP/2.0\r\n' +
            'Via: SIP/2.0/WSS ' + CONFIG.host + ';branch=' + bb + '\r\n' +
            'Max-Forwards: 70\r\n' +
            'From: <sip:' + CONFIG.user + '@' + CONFIG.host + '>;tag=' + localTag + '\r\n' +
            'To: ' + toHeader + (toTag ? ';tag=' + toTag : '') + '\r\n' +
            'Call-ID: ' + callId + '\r\n' +
            'CSeq: ' + cseq + ' BYE\r\n' +
            'Content-Length: 0\r\n\r\n');
          setTimeout(() => { ws.close(); process.exit(0); }, 2000);
        }, 3000);
        return;
      }
      if (msg.code === 401 || msg.code === 407) {
        const ahn = msg.code === 407 ? 'proxy-authenticate' : 'www-authenticate';
        const a = parseWWWAuth(msg.headers[ahn] || '');
        const nc = '00000001', cn = crypto.randomBytes(4).toString('hex');
        const dn = CONFIG.destination.replace(/\D/g, '');
        const resp = computeDigest({
          username: CONFIG.user, password: CONFIG.password,
          realm: a.realm || CONFIG.realm, method: 'INVITE',
          uri: 'sip:' + dn + '@' + CONFIG.host, nonce: a.nonce, nc, cnonce: cn,
          qop: a.qop ? 'auth' : null
        });
        const prefix = msg.code === 407 ? 'Proxy-Authorization' : 'Authorization';
        let ah = prefix + ': Digest username="' + CONFIG.user + '",realm="' + (a.realm || CONFIG.realm) +
                 '",nonce="' + a.nonce + '",uri="sip:' + dn + '@' + CONFIG.host + '",response="' + resp + '"';
        if (a.qop)       ah += ',qop=auth,nc=' + nc + ',cnonce="' + cn + '"';
        if (a.algorithm) ah += ',algorithm=' + a.algorithm;
        if (a.opaque)    ah += ',opaque="' + a.opaque + '"';
        cseq++; branch = generateBranch();
        log('>> INVITE (auth)');
        ws.send(buildINVITE(CONFIG.destination, buildSDP(), ah));
        return;
      }
      if (msg.code >= 400) return finish(
        msg.code === 486 || msg.code === 603 ? 'busy' :
        msg.code === 404 || msg.code === 484 ? 'invalid_number' : 'rejected',
        'Codigo: ' + msg.code
      );
    }
    if (msg.type === 'request' && msg.method === 'BYE') {
      clearTimeout(answerTimer);
      return finish('no_answer', 'Cancelado pelo servidor');
    }
  }

  if (state === 'answered' && msg.type === 'request' && msg.method === 'BYE') {
    ws.close(); process.exit(0);
  }
}

function doInvite() {
  state = 'calling'; callId = generateCallId(); cseq = 1;
  branch = generateBranch(); localTag = generateTag();
  log('>> INVITE => ' + CONFIG.destination);
  ws.send(buildINVITE(CONFIG.destination, buildSDP()));
  answerTimer = setTimeout(() => {
    if (!callAnswered) finish('no_answer', 'Sem resposta em ' + CONFIG.answerTimeout + 's');
  }, CONFIG.answerTimeout * 1000);
}

function finish(status, message) {
  clearTimeout(answerTimer);
  output(Object.assign({ status, callId, destination: CONFIG.destination }, message ? { message } : {}));
  try { ws.close(); } catch (_) {}
  process.exit(0);
}

log('Sofia SIP Dialer v2 — ' + CONFIG.destination);
ws = new SIPWebSocket(CONFIG.host, CONFIG.port);
ws.onopen    = () => { state = 'registering'; log('>> REGISTER'); ws.send(buildREGISTER()); };
ws.onmessage = (msg) => onSIPMessage(msg);
ws.onerror   = (e) => finish('error', 'Erro: ' + e.message);
ws.onclose   = () => { if (state !== 'answered' && !callAnswered) finish('error', 'Conexao fechada'); };
ws.connect();
setTimeout(() => finish('error', 'Timeout global'), (CONFIG.answerTimeout + 15) * 1000);
