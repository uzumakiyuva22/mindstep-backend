const router = require('express').Router();
const ctrl = require('../controllers/task');
router.post('/task/run', ctrl.runTask);
router.post('/task/submit', ctrl.submitTask);
router.get('/course/:slug/progress/:userId', ctrl.courseProgress);
module.exports = router;
