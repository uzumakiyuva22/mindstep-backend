module.exports = function checkHTML(code) {
  const hasH1 = /<h1>.*<\/h1>/i.test(code);
  const hasP = /<p>.*<\/p>/i.test(code);

  if (hasH1 && hasP) {
    return {
      success: true,
      output: "HTML structure is correct"
    };
  }

  return {
    success: false,
    output: "Missing <h1> or <p> tag"
  };
};
