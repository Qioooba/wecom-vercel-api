const crypto = require('crypto');

const TOKEN = process.env.TOKEN;
const AES_KEY = process.env.ENCODING_AES_KEY;
const CORP_ID = process.env.CORPID;

function sha1(str) {
  return crypto.createHash('sha1').update(str).digest('hex');
}

function verifySignature(token, timestamp, nonce, encrypt, signature) {
  const arr = [token, timestamp, nonce, encrypt].sort();
  return sha1(arr.join('')) === signature;
}

function aesDecrypt(encrypted, aesKey) {
  const key = Buffer.from(aesKey + '=', 'base64');
  const iv = key.slice(0, 16);
  const encryptedBuffer = Buffer.from(encrypted, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  let decrypted = decipher.update(encryptedBuffer);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

function decryptMsg(encryptedMsg) {
  const decrypted = aesDecrypt(encryptedMsg, AES_KEY);
  const padLen = decrypted[decrypted.length - 1];
  const unpadded = decrypted.slice(0, decrypted.length - padLen);
  const msgLen = unpadded.readUInt32BE(16);
  const msg = unpadded.slice(20, 20 + msgLen).toString('utf8');
  const receiveId = unpadded.slice(20 + msgLen).toString('utf8');
  if (receiveId !== CORP_ID) throw new Error('receiveId不匹配');
  return msg;
}

module.exports = (req, res) => {
  const { msg_signature, timestamp, nonce, echostr } = req.query;
  
  if (req.method === 'GET' && echostr) {
    try {
      if (!verifySignature(TOKEN, timestamp, nonce, echostr, msg_signature)) {
        return res.status(403).send('fail');
      }
      const decrypted = decryptMsg(echostr);
      return res.status(200).send(decrypted);
    } catch (error) {
      console.error('验证失败:', error);
      return res.status(500).send('fail');
    }
  }
  
  if (req.method === 'POST') {
    return res.status(200).send('success');
  }
  
  res.status(200).send('Hello WeCom!');
};