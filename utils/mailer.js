const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function sendVerificationEmail(to, code) {
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: "Seu código de verificação",
    html: `<p>Seu código de verificação é: <b>${code}</b><br>Expira em 15 minutos.</p>`,
  });
}

module.exports = { sendVerificationEmail };
