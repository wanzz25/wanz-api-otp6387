'use strict';
// Kirim email OTP. Pilih salah satu lewat environment:
//   A) BREVO_API_KEY  -> API HTTP Brevo (disarankan di Vercel, tidak butuh port SMTP)
//   B) SMTP_HOST + SMTP_USER + SMTP_PASS -> SMTP biasa (Gmail App Password, Brevo SMTP, dll)
const axios = require('axios');

const env = process.env;
const FROM_EMAIL = (env.MAIL_FROM || env.SMTP_USER || '').trim();
const FROM_NAME = (env.MAIL_FROM_NAME || 'Wanz Api').trim();
const useBrevo = !!env.BREVO_API_KEY;
const useSmtp = !useBrevo && !!(env.SMTP_HOST && env.SMTP_USER && env.SMTP_PASS);

const ready = !!FROM_EMAIL && (useBrevo || useSmtp);
const provider = useBrevo ? 'brevo' : useSmtp ? 'smtp' : 'none';

let transport = null;
function getTransport() {
  if (!transport) {
    const nodemailer = require('nodemailer');
    const port = parseInt(env.SMTP_PORT, 10) || 465;
    transport = nodemailer.createTransport({
      host: env.SMTP_HOST, port, secure: port === 465,
      auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
      connectionTimeout: 10000, socketTimeout: 15000
    });
  }
  return transport;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function otpHtml(name, code, minutes) {
  return `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;background:#111;color:#f4f4f5;border-radius:12px">
<h2 style="margin:0 0 12px">Wanz Api</h2>
<p>Halo ${esc(name)}, ini kode verifikasi akunmu:</p>
<p style="font-size:34px;letter-spacing:8px;font-weight:700;margin:16px 0;color:#fff">${esc(code)}</p>
<p style="color:#9ca3af;font-size:13px">Berlaku ${minutes} menit. Jangan bagikan kode ini ke siapa pun. Abaikan email ini kalau kamu tidak mendaftar.</p></div>`;
}

async function sendOtp(to, name, code, minutes) {
  if (!ready) throw new Error('Pengiriman email belum dikonfigurasi');
  const subject = `Kode verifikasi Wanz Api: ${code}`;
  const html = otpHtml(name, code, minutes);
  const text = `Kode verifikasi Wanz Api: ${code}\nBerlaku ${minutes} menit. Jangan bagikan ke siapa pun.`;

  if (useBrevo) {
    const r = await axios.post('https://api.brevo.com/v3/smtp/email', {
      sender: { name: FROM_NAME, email: FROM_EMAIL },
      to: [{ email: to }],
      subject, htmlContent: html, textContent: text
    }, { headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 10000, validateStatus: () => true });
    if (r.status < 200 || r.status >= 300) throw new Error('Brevo ' + r.status + ': ' + JSON.stringify(r.data).slice(0, 200));
    return;
  }
  await getTransport().sendMail({ from: `"${FROM_NAME}" <${FROM_EMAIL}>`, to, subject, text, html });
}

module.exports = { ready, provider, sendOtp };
