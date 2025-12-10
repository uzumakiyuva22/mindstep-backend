const fs = require('fs');
const safeUnlink = (fp) => {
  try { if (fp && fs.existsSync(fp)) fs.unlinkSync(fp); } catch(e){}
};
module.exports = { safeUnlink };
