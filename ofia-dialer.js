/**
 * Sofia SIP Dialer — SuperCotação / Grupo Sandri
 * 
 * Conecta via WebSocket SIP na Nvoip, registra o ramal e disca para um lead.
 * Roda no servidor do n8n via Execute Command node.
 * 
 * Uso:
 *   node sofia-dialer.js <numero_destino> [timeout_segundos]
 * 
 * Exemplo:
 *   node sofia-dialer.js 47991234567 30
 * 
 * Saída (JSON para o n8n capturar):
 *   {"status":"answered","callId":"xxx","duration":0}
 *   {"status":"no_answer","callId":"xxx"}
 *   {"status":"rejected","callId":"xxx"}
 *   {"status":"error","message":"..."}
 */

'use strict';

const crypto = require('crypto');
const tls    = require('tls');

// ─── Configuração ────────────────────────────────────────────────────────────
const CONFIG = {
  // Credenciais SIP da Nvoip
  user:     '146482001',
  password: 'c5dabea1',
  host:     'app.nvoip.com.br',
  port:     7443,
  realm:    'app.nvoip.com.br',

  // Número de saída (CallerID)
  callerId: '+554720190290',

  // Destino: passa via argumento de linha de comando
  destination: process.argv[2] || null,

  // Timeout para atendimento (segundos)
  answerTimeout: parseInt(process.argv[3] || '30', 10),
};

if (!CONFIG.destination) {
  output({ status: 'error', message: 'Numero de destino nao informado. Uso: node sofia-dialer.js <numero>' });
  process.exit(1);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function output(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function log(msg) {
  process.stderr.write('[Sofia SIP] ' + msg + '\n');
}

function generateCallId() {
  return crypto.randomBytes(12).toString('hex') + '@' + CONFIG.host;
}

function generateTag() {
  return crypto.randomBytes(8).toString('hex');
}

function generateBranch() {
  return 'z9hG4bK' + crypto.randomBytes(8).toString('hex');
}

// MD5 para digest auth
function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function computeDigest({ username, password, realm, method, uri, nonce, nc, cnonce, qop }) {
  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  if (qop) {
    return md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  }
  return md5(`${ha1}:${nonce}:${ha2}`);
}

function parseWWWAuth(header) {
  const result = {};
  const patterns = {
    realm:     /realm="([^"]+)"/,
    nonce:     /nonce="([^"]+)"/,
    qop:       /qop="([^"]+)"/,
    algorithm: /algorithm=([^\s,]+)/,
    opaque:    /opaque="([^"]+)"/,
  };
  for (const [key, re] of Object.entries(patterns)) {
    const m = header.match(re);
    if (m) result[key] = m[1];
  }
  return result;
}

// ─── Estado da sessão SIP ─────────────────────────────────────────────────────
let cseq       = 1;
let callId     = generateCallId();
let localTag   = generateTag();
let branch     = generateBranch();
let registered = false;
let callStarted = false;
let callAnswered = false;
let answerTimer  = null;

// ─── Conexão WebSocket SIP (implementação manual sobre TLS) ──────────────────
// O protocolo SIP over WebSocket (RFC 7118) envia mensagens SIP como texto
// sobre o frame WebSocket. Node 22 tem WebSocket nativo mas vamos usar
// a implementação manual sobre TLS para ter controle total do handshake SIP.

class SIPWebSocket {
  constructor(host, port) {
    this.host   = host;
    this.port   = port;
    this.socket = null;
    this.buffer = '';
    this.onmessage = null;
    this.onopen    = null;
    this.onclose   = null;
    this.onerror   = null;

    // Estado do handshake WebSocket
    this._wsKey      = crypto.randomBytes(16).toString('base64');
    this._upgraded   = false;
    this._frameBuffer = Buffer.alloc(0);
  }

  connect() {
    log(`Conectando em ${this.host}:${this.port}...`);
    this.socket = tls.connect({
      host:               this.host,
      port:               this.port,
      rejectUnauthorized: false,   // Nvoip pode usar cert self-signed
    });

    this.socket.on('secureConnect', () => {
      log('TLS conectado. Fazendo upgrade WebSocket...');
      // Enviar HTTP Upgrade request (handshake WebSocket)
      const req = [
        `GET / HTTP/1.1`,
        `Host: ${this.host}:${this.port}`,
        `Upgrade: websocket`,
        `Connection: Upgrade`,
        `Sec-WebSocket-Key: ${this._wsKey}`,
        `Sec-WebSocket-Version: 13`,
        `Sec-WebSocket-Protocol: sip`,
        `\r\n`,
      ].join('\r\n');
      this.socket.write(req);
    });

    this.socket.on('data', (data) => {
      if (!this._upgraded) {
        // Processar resposta do handshake HTTP
        const text = data.toString();
        if (text.includes('101 Switching Protocols')) {
          log('WebSocket upgrade OK. Conexão SIP estabelecida.');
          this._upgraded = true;
          if (this.onopen) this.onopen();
        } else {
          log('Resposta HTTP inesperada: ' + text.substring(0, 200));
          if (this.onerror) this.onerror(new Error('WS upgrade falhou: ' + text.substring(0, 100)));
        }
        return;
      }
      // Processar frames WebSocket
      this._frameBuffer = Buffer.concat([this._frameBuffer, data]);
      this._processFrames();
    });

    this.socket.on('error', (err) => {
      log('Erro TLS/Socket: ' + err.message);
      if (this.onerror) this.onerror(err);
    });

    this.socket.on('close', () => {
      log('Conexão fechada.');
      if (this.onclose) this.onclose();
    });
  }

  _processFrames() {
    // Parser de frame WebSocket (RFC 6455)
    while (this._frameBuffer.length >= 2) {
      const b0 = this._frameBuffer[0];
      const b1 = this._frameBuffer[1];
      // const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0F;
      const masked  = (b1 & 0x80) !== 0;
      let payloadLen = b1 & 0x7F;
      let offset = 2;

      if (payloadLen === 126) {
        if (this._frameBuffer.length < 4) break;
        payloadLen = this._frameBuffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this._frameBuffer.length < 10) break;
        payloadLen = Number(this._frameBuffer.readBigUInt64BE(2));
        offset = 10;
      }

      const maskLen = masked ? 4 : 0;
      if (this._frameBuffer.length < offset + maskLen + payloadLen) break;

      let payload;
      if (masked) {
        const mask = this._frameBuffer.slice(offset, offset + 4);
        offset += 4;
        payload = Buffer.alloc(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          payload[i] = this._frameBuffer[offset + i] ^ mask[i % 4];
        }
      } else {
        payload = this._frameBuffer.slice(offset, offset + payloadLen);
      }

      this._frameBuffer = this._frameBuffer.slice(offset + payloadLen);

      if (opcode === 0x1 || opcode === 0x0) { // text ou continuation
        const msg = payload.toString('utf8');
        if (this.onmessage) this.onmessage(msg);
      } else if (opcode === 0x8) { // close
        log('Frame close recebido.');
        if (this.onclose) this.onclose();
      } else if (opcode === 0x9) { // ping
        this._sendPong(payload);
      }
    }
  }

  send(text) {
    if (!this.socket || !this._upgraded) {
      log('AVISO: tentou enviar antes de conectar');
      return;
    }
    const payload = Buffer.from(text, 'utf8');
    const len     = payload.length;
    // Cliente DEVE mascarar (RFC 6455)
    const mask    = crypto.randomBytes(4);
    let header;

    if (len < 126) {
      header = Buffer.alloc(6);
      header[0] = 0x81; // FIN + opcode text
      header[1] = 0x80 | len;
      mask.copy(header, 2);
    } else if (len < 65536) {
      header = Buffer.alloc(8);
      header[0] = 0x81;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
      mask.copy(header, 4);
    } else {
      header = Buffer.alloc(14);
      header[0] = 0x81;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(len), 2);
      mask.copy(header, 10);
    }

    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      masked[i] = payload[i] ^ mask[i % 4];
    }

    this.socket.write(Buffer.concat([header, masked]));
  }

  _sendPong(data) {
    const header = Buffer.from([0x8A, 0x00]);
    this.socket.write(header);
  }

  close() {
    if (this.socket) {
      try {
        // Enviar frame close
        this.socket.write(Buffer.from([0x88, 0x00]));
        this.socket.destroy();
      } catch (_) {}
    }
  }
}

// ─── Mensagens SIP ────────────────────────────────────────────────────────────
function buildREGISTER(authHeader = '') {
  const via = `SIP/2.0/WSS ${CONFIG.host};branch=${branch};rport`;
  const from = `<sip:${CONFIG.user}@${CONFIG.host}>;tag=${localTag}`;
  const to   = `<sip:${CONFIG.user}@${CONFIG.host}>`;
  const contact = `<sip:${CONFIG.user}@${CONFIG.host};transport=wss>`;

  const lines = [
    `REGISTER sip:${CONFIG.host} SIP/2.0`,
    `Via: ${via}`,
    `Max-Forwards: 70`,
    `From: ${from}`,
    `To: ${to}`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} REGISTER`,
    `Contact: ${contact}`,
    `Expires: 60`,
    `User-Agent: Sofia-SDR/1.0`,
    `Content-Length: 0`,
  ];

  if (authHeader) lines.splice(7, 0, authHeader);

  return lines.join('\r\n') + '\r\n\r\n';
}

function buildINVITE(destination, sdp, authHeader = '') {
  const destNum = destination.replace(/\D/g, '');
  const toUri   = `sip:${destNum}@${CONFIG.host}`;
  branch        = generateBranch(); // novo branch para INVITE
  const via     = `SIP/2.0/WSS ${CONFIG.host};branch=${branch};rport`;
  const from    = `<sip:${CONFIG.user}@${CONFIG.host}>;tag=${localTag}`;
  const to      = `<${toUri}>`;
  const contact = `<sip:${CONFIG.user}@${CONFIG.host};transport=wss>`;

  const lines = [
    `INVITE ${toUri} SIP/2.0`,
    `Via: ${via}`,
    `Max-Forwards: 70`,
    `From: ${from}`,
    `To: ${to}`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} INVITE`,
    `Contact: ${contact}`,
    `P-Asserted-Identity: <sip:${CONFIG.callerId}@${CONFIG.host}>`,
    `Content-Type: application/sdp`,
    `User-Agent: Sofia-SDR/1.0`,
    `Content-Length: ${Buffer.byteLength(sdp)}`,
  ];

  if (authHeader) lines.splice(9, 0, authHeader);

  return lines.join('\r\n') + '\r\n\r\n' + sdp;
}

function buildACK(toHeader, toTag) {
  const toUri  = `sip:${CONFIG.destination.replace(/\D/g, '')}@${CONFIG.host}`;
  const branchAck = generateBranch();
  const lines = [
    `ACK ${toUri} SIP/2.0`,
    `Via: SIP/2.0/WSS ${CONFIG.host};branch=${branchAck}`,
    `Max-Forwards: 70`,
    `From: <sip:${CONFIG.user}@${CONFIG.host}>;tag=${localTag}`,
    `To: ${toHeader}${toTag ? ';tag=' + toTag : ''}`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} ACK`,
    `Content-Length: 0`,
  ];
  return lines.join('\r\n') + '\r\n\r\n';
}

function buildBYE(toHeader, toTag) {
  const toUri  = `sip:${CONFIG.destination.replace(/\D/g, '')}@${CONFIG.host}`;
  cseq++;
  const branchBye = generateBranch();
  const lines = [
    `BYE ${toUri} SIP/2.0`,
    `Via: SIP/2.0/WSS ${CONFIG.host};branch=${branchBye}`,
    `Max-Forwards: 70`,
    `From: <sip:${CONFIG.user}@${CONFIG.host}>;tag=${localTag}`,
    `To: ${toHeader}${toTag ? ';tag=' + toTag : ''}`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} BYE`,
    `Content-Length: 0`,
  ];
  return lines.join('\r\n') + '\r\n\r\n';
}

// SDP mínimo para sinalizar a chamada (sem áudio local — a ElevenLabs vai injetar)
function buildSDP() {
  const sessionId = Date.now();
  return [
    'v=0',
    `o=sofia ${sessionId} ${sessionId} IN IP4 ${CONFIG.host}`,
    's=Sofia SDR',
    `c=IN IP4 ${CONFIG.host}`,
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

// Parsear resposta SIP
function parseSIP(msg) {
  const lines = msg.split('\r\n');
  const first = lines[0];
  const result = { headers: {}, body: '', raw: msg };

  // Status line ou Request line
  const statusMatch = first.match(/SIP\/2\.0 (\d+) (.*)/);
  const requestMatch = first.match(/^(\w+) (sip:[^\s]+) SIP\/2\.0/);

  if (statusMatch) {
    result.type   = 'response';
    result.code   = parseInt(statusMatch[1], 10);
    result.reason = statusMatch[2];
  } else if (requestMatch) {
    result.type   = 'request';
    result.method = requestMatch[1];
    result.uri    = requestMatch[2];
  }

  // Headers
  let bodyStart = false;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === '') { bodyStart = true; continue; }
    if (bodyStart) { result.body += lines[i] + '\r\n'; continue; }
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx > 0) {
      const key = lines[i].substring(0, colonIdx).trim().toLowerCase();
      const val = lines[i].substring(colonIdx + 1).trim();
      result.headers[key] = val;
    }
  }

  return result;
}

// ─── Máquina de estados SIP ──────────────────────────────────────────────────
let ws;
let state    = 'idle';
let toHeader = '';
let toTag    = '';

function onSIPMessage(raw) {
  log(`<< ${raw.split('\r\n')[0]}`);
  const msg = parseSIP(raw);

  // ── REGISTER flow ──────────────────────────────────────────────────────────
  if (state === 'registering') {
    if (msg.type === 'response' && msg.code === 401) {
      // Digest challenge para REGISTER
      const wwwAuth = msg.headers['www-authenticate'];
      if (!wwwAuth) { return finish('error', 'Sem WWW-Authenticate no 401'); }

      const authParams = parseWWWAuth(wwwAuth);
      const nc     = '00000001';
      const cnonce = crypto.randomBytes(4).toString('hex');
      const qop    = authParams.qop ? 'auth' : null;
      const uri    = `sip:${CONFIG.host}`;

      const response = computeDigest({
        username: CONFIG.user,
        password: CONFIG.password,
        realm:    authParams.realm || CONFIG.realm,
        method:   'REGISTER',
        uri,
        nonce:    authParams.nonce,
        nc, cnonce,
        qop,
      });

      let authHeader = `Authorization: Digest username="${CONFIG.user}",realm="${authParams.realm || CONFIG.realm}",nonce="${authParams.nonce}",uri="${uri}",response="${response}"`;
      if (qop) authHeader += `,qop=${qop},nc=${nc},cnonce="${cnonce}"`;
      if (authParams.algorithm) authHeader += `,algorithm=${authParams.algorithm}`;
      if (authParams.opaque)    authHeader += `,opaque="${authParams.opaque}"`;

      cseq++;
      branch = generateBranch();
      log('>> REGISTER (com auth)');
      ws.send(buildREGISTER(authHeader));
      return;
    }

    if (msg.type === 'response' && msg.code === 200) {
      log('Registrado com sucesso!');
      registered = true;
      state = 'registered';
      // Disparar INVITE
      doInvite();
      return;
    }

    if (msg.type === 'response' && msg.code >= 400) {
      return finish('error', `REGISTER rejeitado: ${msg.code} ${msg.reason}`);
    }
  }

  // ── INVITE flow ────────────────────────────────────────────────────────────
  if (state === 'calling') {
    if (msg.type === 'response') {
      // Provisional (180 Ringing, 183 Progress)
      if (msg.code >= 100 && msg.code < 200) {
        log(`Provisional: ${msg.code} ${msg.reason}`);
        // Capturar To header para ACK
        if (msg.headers['to']) toHeader = msg.headers['to'].split(';tag=')[0];
        return;
      }

      // 200 OK — atendeu!
      if (msg.code === 200) {
        clearTimeout(answerTimer);
        callAnswered = true;

        // Extrair tag do To
        const toFull = msg.headers['to'] || '';
        const tagMatch = toFull.match(/;tag=([^\s;]+)/);
        toTag    = tagMatch ? tagMatch[1] : '';
        toHeader = toFull.split(';tag=')[0];

        log('Chamada ATENDIDA! Enviando ACK...');
        ws.send(buildACK(toHeader, toTag));
        state = 'answered';

        output({
          status:      'answered',
          callId:      callId,
          destination: CONFIG.destination,
          duration:    0,
          note:        'Chamada atendida — conectar audio ElevenLabs agora',
        });

        // Encerrar após 3s (para teste) — em produção o n8n controla via BYE
        // O n8n receberá o JSON acima e tomará a ação de conectar ElevenLabs
        setTimeout(() => {
          log('Encerrando chamada de teste...');
          ws.send(buildBYE(toHeader, toTag));
          setTimeout(() => { ws.close(); process.exit(0); }, 2000);
        }, 3000);

        return;
      }

      // 401/407 — auth para INVITE
      if (msg.code === 401 || msg.code === 407) {
        const authHdrName = msg.code === 407 ? 'proxy-authenticate' : 'www-authenticate';
        const wwwAuth     = msg.headers[authHdrName];
        if (!wwwAuth) { return finish('error', 'Sem auth challenge no ' + msg.code); }

        const authParams = parseWWWAuth(wwwAuth);
        const nc     = '00000001';
        const cnonce = crypto.randomBytes(4).toString('hex');
        const qop    = authParams.qop ? 'auth' : null;
        const destNum = CONFIG.destination.replace(/\D/g, '');
        const uri    = `sip:${destNum}@${CONFIG.host}`;

        const response = computeDigest({
          username: CONFIG.user,
          password: CONFIG.password,
          realm:    authParams.realm || CONFIG.realm,
          method:   'INVITE',
          uri,
          nonce:    authParams.nonce,
          nc, cnonce, qop,
        });

        let authHeader = msg.code === 407
          ? `Proxy-Authorization: Digest username="${CONFIG.user}",realm="${authParams.realm || CONFIG.realm}",nonce="${authParams.nonce}",uri="${uri}",response="${response}"`
          : `Authorization: Digest username="${CONFIG.user}",realm="${authParams.realm || CONFIG.realm}",nonce="${authParams.nonce}",uri="${uri}",response="${response}"`;
        if (qop) authHeader += `,qop=${qop},nc=${nc},cnonce="${cnonce}"`;
        if (authParams.algorithm) authHeader += `,algorithm=${authParams.algorithm}`;
        if (authParams.opaque)    authHeader += `,opaque="${authParams.opaque}"`;

        cseq++;
        branch = generateBranch();
        log('>> INVITE (com auth)');
        ws.send(buildINVITE(CONFIG.destination, buildSDP(), authHeader));
        return;
      }

      // 486 Busy, 480 Unavailable, 404 Not Found, 603 Decline...
      if (msg.code === 486 || msg.code === 600 || msg.code === 603) {
        return finish('busy', `Ocupado/Rejeitado: ${msg.code} ${msg.reason}`);
      }

      if (msg.code === 404 || msg.code === 484) {
        return finish('invalid_number', `Número inválido: ${msg.code} ${msg.reason}`);
      }

      if (msg.code >= 400) {
        return finish('rejected', `Chamada rejeitada: ${msg.code} ${msg.reason}`);
      }
    }

    // BYE recebido enquanto chamando (cancelamento remoto)
    if (msg.type === 'request' && msg.method === 'BYE') {
      clearTimeout(answerTimer);
      return finish('no_answer', 'Chamada cancelada pelo servidor');
    }
  }

  // ── Answered — BYE recebido pelo lado remoto ───────────────────────────────
  if (state === 'answered') {
    if (msg.type === 'request' && msg.method === 'BYE') {
      log('BYE recebido — chamada encerrada pelo lead.');
      ws.close();
      process.exit(0);
    }
  }
}

function doInvite() {
  state = 'calling';
  callId = generateCallId(); // novo call-id para o INVITE
  cseq   = 1;
  branch = generateBranch();
  localTag = generateTag();

  log(`>> INVITE para ${CONFIG.destination}`);
  ws.send(buildINVITE(CONFIG.destination, buildSDP()));

  // Timer de sem resposta
  answerTimer = setTimeout(() => {
    if (!callAnswered) {
      finish('no_answer', `Sem resposta em ${CONFIG.answerTimeout}s`);
    }
  }, CONFIG.answerTimeout * 1000);
}

function finish(status, message) {
  clearTimeout(answerTimer);
  const obj = { status, callId, destination: CONFIG.destination };
  if (message) obj.message = message;
  output(obj);
  try { ws.close(); } catch (_) {}
  process.exit(status === 'answered' ? 0 : 0);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
log(`Sofia SIP Dialer iniciando — destino: ${CONFIG.destination}`);

ws = new SIPWebSocket(CONFIG.host, CONFIG.port);

ws.onopen = () => {
  log('WebSocket aberto. Enviando REGISTER...');
  state = 'registering';
  log('>> REGISTER');
  ws.send(buildREGISTER());
};

ws.onmessage = (msg) => {
  onSIPMessage(msg);
};

ws.onerror = (err) => {
  finish('error', 'Erro WebSocket: ' + err.message);
};

ws.onclose = () => {
  if (state !== 'answered' && !callAnswered) {
    finish('error', 'Conexão fechada inesperadamente');
  }
};

ws.connect();

// Timeout global de segurança
setTimeout(() => {
  finish('error', 'Timeout global — sem resposta do servidor SIP');
}, (CONFIG.answerTimeout + 15) * 1000);
