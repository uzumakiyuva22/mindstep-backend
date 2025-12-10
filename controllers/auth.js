const bcrypt = require('bcryptjs');
const User = require('../models/User');

exports.signup = async (req,res)=>{
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success:false, error:'Missing fields' });
    const exists = await User.findOne({ $or:[{username},{email}] }).lean();
    if (exists) return res.status(409).json({ success:false, error:'User exists' });
    const user = await User.create({ username, email, password: bcrypt.hashSync(password,10), image: req.body.image || null });
    res.json({ success:true, user:{ _id:user._id, username:user.username, email:user.email, image:user.image }});
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};

exports.login = async (req,res)=>{
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ success:false, error:'Missing fields' });
    const user = await User.findOne({ $or:[{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(401).json({ success:false, error:'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success:false, error:'Invalid credentials' });
    res.json({ success:true, user:{ _id:user._id, username:user.username, email:user.email, image:user.image }});
  } catch (e) { console.error(e); res.status(500).json({ success:false, error:'Server error' }); }
};
