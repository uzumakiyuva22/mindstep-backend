const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

module.exports = function generateCertificate({
  username,
  courseTitle,
  certificateId
}) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: "A4", layout: "landscape" });

      const fileName = `certificate-${certificateId}.pdf`;
      const filePath = path.join(__dirname, "../certificates", fileName);

      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // Background
      doc.rect(0, 0, 842, 595).fill("#0b1220");

      // Border
      doc
        .lineWidth(6)
        .rect(30, 30, 782, 535)
        .stroke("#00e5ff");

      // Title
      doc
        .fillColor("#ffffff")
        .fontSize(36)
        .text("Certificate of Completion", {
          align: "center",
          valign: "center"
        });

      doc.moveDown(2);

      // User name
      doc
        .fontSize(28)
        .fillColor("#00e5ff")
        .text(username, { align: "center" });

      doc.moveDown(1);

      doc
        .fontSize(18)
        .fillColor("#ffffff")
        .text("has successfully completed the course", {
          align: "center"
        });

      doc.moveDown(1);

      // Course title
      doc
        .fontSize(24)
        .fillColor("#ff2d55")
        .text(courseTitle, { align: "center" });

      doc.moveDown(2);

      // Footer
      doc
        .fontSize(12)
        .fillColor("#cccccc")
        .text(`Certificate ID: ${certificateId}`, {
          align: "center"
        });

      doc.end();

      stream.on("finish", () => resolve(filePath));
    } catch (err) {
      reject(err);
    }
  });
};
