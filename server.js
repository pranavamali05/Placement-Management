const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// === NEW: Serve HTML files from this folder ===
app.use(express.static(__dirname));
// ==============================================

// 1. Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', 
    password: '', 
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
            res.status(201).json({ message: "Student account created!" });
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

// === NEW: Listen on 0.0.0.0 for network access ===
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running locally on http://localhost:${PORT}`);
});
// =================================================



// from flask import Flask, request, jsonify
// from flask_cors import CORS
// from flask_bcrypt import Bcrypt
// import mysql.connector
// from mysql.connector import Error

// app = Flask(__name__)
// CORS(app)  # Enables CORS for all routes
// bcrypt = Bcrypt(app)

// # 1. Database Connection Configuration
// db_config = {
//     'host': 'localhost',
//     'user': 'root',
//     'password': '',
//     'database': 'placement_db'
// }

// def get_db_connection():
//     """Helper function to open a connection to the MySQL database."""
//     try:
//         connection = mysql.connector.connect(**db_config)
//         return connection
//     except Error as e:
//         print(f"Error connecting to MySQL: {e}")
//         return None

// # Test initial connection on startup
// initial_conn = get_db_connection()
// if initial_conn and initial_conn.is_connected():
//     print("Connected securely to MySQL Database.")
//     initial_conn.close()


// # 2. Secure Login API
// @app.route('/api/login', methods=['POST'])
// def login():
//     data = request.get_json() or {}
//     role = data.get('role')
//     identifier = data.get('identifier')
//     password = data.get('password')

//     if not role or not identifier or not password:
//         return jsonify({"error": "Please provide role, identifier, and password."}), 400

//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error."}), 500
    
//     cursor = conn.cursor(dictionary=True) # dictionary=True makes results behave like JS objects

//     try:
//         if role == 'admin':
//             sql = "SELECT * FROM admins WHERE username = %s"
//             cursor.execute(sql, (identifier,))
//             admin = cursor.fetchone()

//             if not admin:
//                 return jsonify({"error": "Admin not found."}), 401

//             # Verify password using Flask-Bcrypt
//             if bcrypt.check_password_hash(admin['password_hash'], password):
//                 return jsonify({"message": "Admin Login Successful", "user": admin['username']})
//             else:
//                 return jsonify({"error": "Incorrect password."}), 401

//         elif role == 'student':
//             sql = "SELECT * FROM students WHERE prn_number = %s"
//             cursor.execute(sql, (identifier,))
//             student = cursor.fetchone()

//             if not student:
//                 return jsonify({"error": "Student not found."}), 401

//             if bcrypt.check_password_hash(student['password'], password):
//                 return jsonify({"message": "Student Login Successful", "user": student['name']})
//             else:
//                 return jsonify({"error": "Incorrect password."}), 401
                
//     except Error as e:
//         return jsonify({"error": f"Database error: {str(e)}"}), 500
//     finally:
//         cursor.close()
//         conn.close()


// # 3. Admin: Get All Students (For Directory & CSV Export)
// @app.route('/api/students', methods=['GET'])
// def get_all_students():
//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error"}), 500
        
//     cursor = conn.cursor(dictionary=True)
//     try:
//         sql = "SELECT * FROM students ORDER BY cgpa DESC"
//         cursor.execute(sql)
//         results = cursor.fetchall()
//         return jsonify(results)
//     except Error as e:
//         print(f"Error fetching students: {e}")
//         return jsonify({"error": "Database error"}), 500
//     finally:
//         cursor.close()
//         conn.close()


// # 4. Student Portal: Get Single Student Data
// @app.route('/api/students/<prn>', methods=['GET'])
// def get_student_by_prn(prn):
//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error"}), 500
        
//     cursor = conn.cursor(dictionary=True)
//     try:
//         sql = "SELECT * FROM students WHERE prn_number = %s"
//         cursor.execute(sql, (prn,))
//         student = cursor.fetchone()
        
//         if not student:
//             return jsonify({"error": "Not found"}), 404
//         return jsonify(student)
//     except Error as e:
//         return jsonify({"error": "Database error"}), 500
//     finally:
//         cursor.close()
//         conn.close()


// # 5. Admin: Create Student Shell (Name, PRN, RegNo only)
// @app.route('/api/students', methods=['POST'])
// def create_student():
//     data = request.get_json() or {}
//     prn = data.get('prn')
//     name = data.get('name')
//     reg_no = data.get('regNo')
//     password = data.get('password')

//     if not prn or not name or not reg_no or not password:
//          return jsonify({"error": "Missing required fields."}), 400

//     try:
//         # Generate bcrypt hash
//         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
//     except Exception:
//         return jsonify({"error": "Encryption error."}), 500

//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error."}), 500
        
//     cursor = conn.cursor()
//     try:
//         sql = "INSERT INTO students (prn_number, name, registration_number, password) VALUES (%s, %s, %s, %s)"
//         cursor.execute(sql, (prn, name, reg_no, hashed_password))
//         conn.commit()  # Required for write transactions in Python MySQL connectors
//         return jsonify({"message": "Student account created!"}), 201
//     except Error as e:
//         # 1062 is MySQL error code for Duplicate Entry
//         if e.errno == 1062:
//             return jsonify({"error": "PRN or Reg No already exists."}), 400
//         return jsonify({"error": "Database error."}), 500
//     finally:
//         cursor.close()
//         conn.close()


// # 6. Student: Update Profile (Self-service)
// @app.route('/api/students/<prn>', methods=['PUT'])
// def update_student(prn):
//     data = request.get_json() or {}
//     email = data.get('email')
//     mobile = data.get('mobile')
//     cgpa = data.get('cgpa')
//     marks_10th = data.get('marks10th')
//     marks_12th = data.get('marks12th')

//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error."}), 500
        
//     cursor = conn.cursor()
//     try:
//         sql = """UPDATE students 
//                  SET email = %s, mobile = %s, cgpa = %s, marks_10th = %s, marks_12th_diploma = %s 
//                  WHERE prn_number = %s"""
//         cursor.execute(sql, (email, mobile, cgpa, marks_10th, marks_12th, prn))
//         conn.commit()
//         return jsonify({"message": "Profile updated!"})
//     except Error:
//         return jsonify({"error": "Update failed."}), 500
//     finally:
//         cursor.close()
//         conn.close()


// # 7. Admin: Delete Student
// @app.route('/api/students/<prn>', methods=['DELETE'])
// def delete_student(prn):
//     conn = get_db_connection()
//     if not conn:
//         return jsonify({"error": "Database error."}), 500
        
//     cursor = conn.cursor()
//     try:
//         sql = "DELETE FROM students WHERE prn_number = %s"
//         cursor.execute(sql, (prn,))
//         conn.commit()
//         return jsonify({"message": "Student deleted."})
//     except Error:
//         return jsonify({"error": "Delete failed."}), 500
//     finally:
//         cursor.close()
//         conn.close()


// if __name__ == '__main__':
//     # Runs the application on http://localhost:3000
//     app.run(port=3000, debug=True)