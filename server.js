const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// 1. Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', 
    password: 'Pranav@1210', 
    database: 'placement_db'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected securely to MySQL Database.');
});

// 2. Secure Login API
app.post('/api/login', (req, res) => {
    const { role, identifier, password } = req.body;

    if (!role || !identifier || !password) {
        return res.status(400).json({ error: "Please provide role, identifier, and password." });
    }

    if (role === 'admin') {
        const sql = "SELECT * FROM admins WHERE username = ?";
        db.query(sql, [identifier], async (err, results) => {
            if (err) return res.status(500).json({ error: "Database error." });
            if (results.length === 0) return res.status(401).json({ error: "Admin not found." });

            const admin = results[0];
            const match = await bcrypt.compare(password, admin.password_hash);
            if (match) res.json({ message: "Admin Login Successful", user: admin.username });
            else res.status(401).json({ error: "Incorrect password." });
        });
    } else if (role === 'student') {
        const sql = "SELECT * FROM students WHERE prn_number = ?";
        db.query(sql, [identifier], async (err, results) => {
            if (err) return res.status(500).json({ error: "Database error." });
            if (results.length === 0) return res.status(401).json({ error: "Student not found." });

            const student = results[0];
            const match = await bcrypt.compare(password, student.password);
            if (match) res.json({ message: "Student Login Successful", user: student.name });
            else res.status(401).json({ error: "Incorrect password." });
        });
    }
});

// 3. Admin: Get All Students (For Directory)
// 3. Admin: Get All Students (Updated to include ALL fields for CSV Export)
app.get('/api/students', (req, res) => {
    // We use SELECT * so that hidden fields like mobile, email, and reg_no 
    // are available for the CSV export function in the frontend.
    const sql = "SELECT * FROM students ORDER BY cgpa DESC"; 
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching students:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
    });
});

// 4. Student Portal: Get Single Student Data
app.get('/api/students/:prn', (req, res) => {
    const prn = req.params.prn;
    const sql = "SELECT * FROM students WHERE prn_number = ?";
    db.query(sql, [prn], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "Not found" });
        res.json(results[0]);
    });
});

// 5. Admin: Create Student Shell (Name, PRN, RegNo only)
app.post('/api/students', async (req, res) => {
    const { prn, name, regNo, password } = req.body;
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const sql = `INSERT INTO students (prn_number, name, registration_number, password) VALUES (?, ?, ?, ?)`;
        db.query(sql, [prn, name, regNo, hashedPassword], (err, results) => {
            if (err) {
                if(err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: "PRN or Reg No already exists." });
                return res.status(500).json({ error: "Database error." });
            }
            res.status(201).json({ message: "Student shell created!" });
        });
    } catch (e) { res.status(500).json({ error: "Encryption error." }); }
});

// 6. Student: Update Profile (Self-service)
app.put('/api/students/:prn', (req, res) => {
    const prn = req.params.prn;
    const { email, mobile, cgpa, marks10th, marks12th } = req.body;
    const sql = "UPDATE students SET email = ?, mobile = ?, cgpa = ?, marks_10th = ?, marks_12th_diploma = ? WHERE prn_number = ?";
    db.query(sql, [email, mobile, cgpa, marks10th, marks12th, prn], (err, result) => {
        if (err) return res.status(500).json({ error: "Update failed." });
        res.json({ message: "Profile updated!" });
    });
});

// 7. Admin: Delete Student
app.delete('/api/students/:prn', (req, res) => {
    const prn = req.params.prn;
    db.query("DELETE FROM students WHERE prn_number = ?", [prn], (err, result) => {
        if (err) return res.status(500).json({ error: "Delete failed." });
        res.json({ message: "Student deleted." });
    });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));