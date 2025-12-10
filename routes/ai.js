const router = require("express").Router();
const { askGPT } = require("../services/openaiService");

router.post("/generate", async (req, res) => {
    const { topic } = req.body;
    const reply = await askGPT(`Generate a beginner lesson for: ${topic}`);
    res.json({ success: true, reply });
});

router.post("/explain", async (req, res) => {
    const { question } = req.body;
    const reply = await askGPT(`Explain this clearly: ${question}`);
    res.json({ success: true, reply });
});

router.post("/hint", async (req, res) => {
    const { code } = req.body;
    const reply = await askGPT(`Give a hint to fix this code:\n${code}`);
    res.json({ success: true, reply });
});

module.exports = router;
