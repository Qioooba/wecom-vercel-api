// Vercel Serverless Function - 企业微信回调处理
// 访问路径: /api/wechat/callback

const crypto = require('crypto');

// 从环境变量读取配置
const TOKEN = process.env.TOKEN;
const AES_KEY = process.env.ENCODING_AES_KEY;
const CORP_ID = process.env.CORPID;

// SHA1签名
function sha1(str) {
  return crypto.createHash('sha1').update(str).digest('hex');
}

// 验证签名
function verifySignature(token, timestamp, nonce, encrypt, signature) {
  const arr = [token, timestamp, nonce, encrypt].sort();
  return sha1(arr.join('')) === signature;
}

// AES解密
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

// 解密消息
function decryptMsg(encryptedMsg) {
  const decrypted = aesDecrypt(encryptedMsg, AES_KEY);
  const padLen = decrypted[decrypted.length - 1];
  const unpadded = decrypted.slice(0, decrypted.length - padLen);
  const msgLen = unpadded.readUInt32BE(16);
  const msg = unpadded.slice(20, 20 + msgLen).toString('utf8');
  const receiveId = unpadded.slice(20 + msgLen).toString('utf8');
  
  if (receiveId !== CORP_ID) {
    throw new Error('receiveId不匹配');
  }
  return msg;
}

module.exports = (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  
  const { msg_signature, timestamp, nonce, echostr } = req.query;
  
  console.log('收到请求:', { method: req.method, query: req.query });
  
  // GET请求 - URL验证
  if (req.method === 'GET' && echostr) {
    try {
      // 1. 验证签名
      if (!verifySignature(TOKEN, timestamp, nonce, echostr, msg_signature)) {
        console.log('签名验证失败');
        return res.status(200).send('fail');
      }
      
      // 2. 解密
      const decrypted = decryptMsg(echostr);
      console.log('解密成功:', decrypted);
      
      // 3. 返回明文
      return res.status(200).send(decrypted);
      
    } catch (error) {
      console.error('解密失败:', error);
      return res.status(200).send('fail');
    }
  }
  
  // POST请求
  if (req.method === 'POST') {
    return res.status(200).send('success');
  }
  
  res.status(200).send('Hello WeCom!');
};