const express = require('express');
const cors = require('cors');
const { default: mongoose } = require('mongoose');
const User = require ('./models/User');
require('dotenv').config();
const jwt =require ('jsonwebtoken');
const app = express();
const bodyParser = require('body-parser');
const jwtSecret ='gdgqsdgvdgvd'
const bcrypt = require('bcrypt');
const bcryptSaltRounds = 10;
const salt = bcrypt.genSaltSync(bcryptSaltRounds);

app.use(express.json());
app.use(cors({
    credentials: true,
    origin:'http://localhost:3000',
}));

mongoose.connect('mongodb://127.0.0.1:27017/Eventify');
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Erreur de connexion à la base de données :'));
db.once('open', () => {
  console.log('Connected to database');
});

app.get('/test',(req,res)=>{
    res.json('test ok')
});

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = bcrypt.hashSync(password, salt);
        const newUser = await User.create({
            username,
            email,
            password: hashedPassword,
        });
        res.json(newUser);
    } catch (error) {
        console.error('Signup failed:', error);
        if (error.code === 11000 && error.keyPattern.username) {
            res.status(400).json({ message: 'Username already exists' });
        } else {
            res.status(500).json({ message: 'Signup failed. Please try again later' });
        }
    }    
});


app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ status: false, message: 'User not registered' });
        }

        const passOk = bcrypt.compareSync(password, user.password);

        if (passOk) {
            jwt.sign({ email: user.email, id: user._id }, jwtSecret, {}, (err, token) => {
                if (err) {
                    console.error('JWT sign error:', err);
                    return res.status(500).json({ status: false, message: 'Internal server error' });
                }
                res.cookie('token', token).json( user );
            });
        } else {
            res.status(401).json({ status: false, message: 'Password incorrect' });
        }
    } catch (error) {
        console.error('Login failed:', error);
        res.status(500).json({ status: false, message: 'An error occurred during login. Please try again later.' });
    }
});




const PORT = process.env.PORT || 4000;

app.listen(PORT,(error)=>{
    if (!error){
        console.log("Server is Running on Port " +PORT)
    }
    else{
        console.log("Error: "+error)
    }
})

    /*const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
        return res.json({ message: "password is incorrect, try again" })
    }
    const token = jwt.sign({ username: user.username }, process.env.KEY, { expiresIn: '1h' })
    res.cookie('token', token, { httpOnly: true, maxAge: 360000 })
    return res.json({ status: true, message: "Login successfully" })
    }
})

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.json({ message: "user not registered" })
        }
        const token = jwt.sign({ id: user._id }, process.env.KEY, { expiresIn: '5m' })

        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'sirine.abdeljelile@gmail.com',
                pass: 'nptv rkna kjsx bxzu'
            }
        });

        var mailOptions = {
            from: 'sirine.abdeljelile@gmail.com',
            to: email,
            subject: 'Reset Password',
            text: 'http://localhost:5173/resetPassword/${token}'
        };

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                return res.json({ message: "error sending email" });
            } else {
                return res.json({ status: true, message: "Email sent" });
            }
        });

    } catch (err) {
        console.log(err)
    }
})

app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const decoded = await jwt.verify(token, process.env.KEY);
        const id = decoded.id;
        const hashpassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate({ _id: id }, { password: hashpassword });
        return res.json({ status: true, message: "updated Password" });
    } catch (err) {
        console.log(err); // Log the error for debugging
        return res.json("Invalid token");
    }
});

const verifyUser = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.json({ status: false, message: "no token" });
        }
        const decoded = await jwt.verify(token, process.env.KEY);
        next()

    } catch (err) {
        return res.json(err)
    }
};
app.get('/verify', verifyUser, (req, res) => {
    return res.json({ status: true, message: "authorized" })
});

app.get('/logout', (req, res) => {
    res.clearCookie('token')
    return res.json({ status: true })
})


*/