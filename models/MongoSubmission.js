const express = require("express");
const router = express.Router();
const MongoSubmission = require("../models/MongoSubmission");

router.post("/insert", async (req, res) => {
  try {
    const { userId, lessonId, document } = req.body;

    const saved = await MongoSubmission.create({
      userId,
      lessonId,
      document
    });

    res.json({ success: true, id: saved._id });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

module.exports = router;
