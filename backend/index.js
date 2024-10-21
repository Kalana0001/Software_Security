const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");  
const jwt = require("jsonwebtoken");  
require('dotenv').config(); 

const app = express();
app.use(cors({
    origin: 'http://localhost:3000', 
}));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));


const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "KAlana#23",
    database: "login_security"
});


const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";


function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    console.log("Received token:", token); 
    if (!token) return res.status(401).json("Access Denied: No Token Provided");

    jwt.verify(token.split(' ')[1], JWT_SECRET, (err, user) => { 
        if (err) {
            console.error("Token verification failed:", err); 
            return res.status(403).json("Invalid Token");
        }
        req.user = user;
        next();
    });
}


function logAction(userId, action) {
    const sql = "INSERT INTO activity_logs (user_id, action) VALUES (?, ?)";
    db.query(sql, [userId, action], (err) => {
        if (err) console.error("Error logging action:", err);
    });
}


app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;
    const sql = "INSERT INTO users (name, email, password) VALUES (?)";
    
    try {
  
        const hashedPassword = await bcrypt.hash(password, 10);
        const values = [name, email, hashedPassword];
        
        db.query(sql, [values], (err) => {
            if (err) {
                return res.status(500).json("Error registering user");
            }
            res.json("User Registered Successfully");
        });
    } catch (err) {
        res.status(500).json("Error hashing password");
    }
});


app.post("/signin", (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ?";
    
    db.query(sql, [email], async (err, data) => {
        if (err) {
            return res.status(500).json("Error");
        }
        if (data.length > 0) {
            const user = data[0];
            
            
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            
            if (!isPasswordCorrect) {
                return res.status(401).json("Fail");
            }
            
          
            const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
            
            
            logAction(user.id, "Signed in");
            
            res.json({ message: "Success", token });
        } else {
            return res.status(401).json("Fail");
        }
    });
});


app.get("/users", authenticateToken, (req, res) => {
   
    const sql = "SELECT * FROM users WHERE id = ?";
    
    db.query(sql, [req.user.id], (err, data) => {
        if (err) {
            return res.status(500).json("Error fetching data");
        }
        
       
        logAction(req.user.id, "Viewed own data");
        
       
        if (data.length > 0) {
            return res.json(data[0]); 
        } else {
            return res.status(404).json("User not found");
        }
    });
});

app.listen(8085, () => {
    console.log("Server is running on port 8085");
});
