const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { check, validationResult } = require('express-validator');
const User = require('./userSchema');
const nodemailer = require('nodemailer');

var app = express();

app.get('/auth', async (req, res) => {
    
    const token = req.header('jwtToken');
    if (!token) {
        return res.status(401).send('Access Denied');
    }

    try {
        const decode = jwt.verify(token, config.get('jwtPrivateKey'));

        const user = await User.findById(decode.id);

        if (!user) {
            return res.status(401).send('Invalid Token');
        }

        return res.status(200).send(decode);
    }
    catch (ex) {
        return res.status(401).send('Invalid Token');
    }
});

// login user
app.post('/auth/loginviaform', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    // console.log(email,password)
    try {
        let user = await User.findOne({ email },{profilePic:1,username:1,password:1,email:1,role:1});
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }
        const payload = {
            id: user.id
        }
        // console.log(user.role,"59")  
        const userInfo={
            profilePic:user.profilePic,
            username:user.username,
            userId:user._id,
            role:user.role
        }
        const {profilePic,username}=user
        jwt.sign(payload, process.env.JWT_SECRET , {
            expiresIn: 360000
        }, (err, token) => {
            if (err) throw err;
            return res.json({email,token,profilePic,username,userInfo});
        });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


app.post('/auth/registerviaform', [
    check('username', 'Please add firstname').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    



    const filteredData = Object.keys(req.body).reduce((acc, key) => {
        if (req.body[key] !== null && req.body[key] !== undefined && req.body[key].length) {
            acc[key] = req.body[key];
        }
        return acc;
    }, {});
    
    try {
        const {email,password}=req.body
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }
        
        user = new User(filteredData);
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();
        const payload = {
           id: user.id
        }
        const userInfo={
            firstName:user.firstName,
            email:user.email
        }
        jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: 360000
        }, (err, token) => {
            if (err) throw err;
            return res.json({ token,userInfo });
        });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Forgot password
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }

        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), {
            expiresIn: 360000
        }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.get("/auth/emailexist/:email",async (req,res)=>{
    const email=req.params.email
    const user = await User.findOne({ email });
    if(user){
        return res.send(false)
    }
    return res.send(true)
})

app.get("/auth/usernameexist/:username",async (req,res)=>{
    const username=req.params.username
    const user = await User.findOne({ username });
    if(user){
        return res.send(false)
    }
    return res.send(true)
})

app.get('/auth/phoneexist/:phone',async (req, res) => {
    const phone = req.params.phone
    const user = await User.findOne({ phone });
    if (user) {
        return res.send(false)
    }
    return res.send(true)
})
app.get("/auth/checktoken/:token",async (req, res) => {
    // get token from headers and decrypt the jwt token to id and cheak if that id is valid
    // header are stored like this { "Authorization": `Bearer ${action.payload}` } }
    const token=req.params.token
    if (!token) {
        return res.status(401).json({ msg: "No token, authorization denied" });
    } 
    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user=await User.findOne({ _id: decoded.id },{email:1,username:1,profilePic:1,role:1});
        if(!user){
            return res.status(401).json({ msg: "No token, authorization denied" });
        }
        const {email,username,profilePic,role}=user
        return res.status(200).json({email,username,profilePic,userId:decoded.id,role});  
    }
    catch(err){
        console.log(err)
        return res.status(401).json({ msg: "No token, authorization denied" });
    }
    
})
module.exports = app