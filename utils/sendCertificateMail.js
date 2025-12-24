const nodemailer = require("nodemailer");

module.exports = async function sendCertificateMail({
  to,
  username,
  courseTitle,
  attachmentPath
}) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: `"MindStep" <${process.env.EMAIL_USER}>`,
    to,
    subject: "🎓 Your Course Completion Certificate",
    html: `
      <h2>Congratulations ${username} 🎉</h2>
      <p>You have successfully completed the course:</p>
      <h3>${courseTitle}</h3>
      <p>Your certificate is attached to this email.</p>
      <p>Keep learning with MindStep 🚀</p>
    `,
    attachments: [
      {
        filename: "certificate.pdf",
        path: attachmentPath
      }
    ]
  });
};
