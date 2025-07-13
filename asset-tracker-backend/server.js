// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Database Connection ---
const MONGO_URI = '';

// --- JWT Secret ---
const JWT_SECRET = 'your_jwt_secret_key_that_is_long_and_random';

// --- Mongoose Schemas ---
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Admin', 'Editor', 'Viewer'], default: 'Viewer' }
});
const EquipmentSchema = new mongoose.Schema({
    assetId: { type: String, required: true, unique: true },
    category: { type: String, required: true },
    status: { type: String, required: true, enum: ['In Use', 'In Stock', 'Damaged', 'E-Waste'] },
    model: { type: String },
    serialNumber: { type: String },
    warrantyInfo: { type: String },
    location: { type: String },
    comment: { type: String },
    assigneeName: { type: String },
    position: { type: String },
    employeeEmail: { type: String },
    phoneNumber: { type: String },
    department: { type: String },
    damageDescription: { type: String },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Equipment = mongoose.model('Equipment', EquipmentSchema);

// --- Function to Seed First Admin User ---
const seedAdminUser = async () => {
    try {
        const adminExists = await User.findOne({ role: 'Admin' });
        if (!adminExists) {
            console.log('No Admin user found. Creating one...');
            const admin = new User({
                email: 'admin@example.com', // Change this to your email
                password: 'password123',   // Change this to a secure password
                role: 'Admin'
            });
            const salt = await bcrypt.genSalt(10);
            admin.password = await bcrypt.hash(admin.password, salt);
            await admin.save();
            console.log('Admin user created successfully!');
            console.log(`Email: ${admin.email}`);
            console.log(`Password: password123`);
        } else {
            console.log('Admin user already exists.');
        }
    } catch (error) {
        console.error('Error seeding admin user:', error);
    }
};

// --- Connect to DB and Seed Admin ---
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('MongoDB connected successfully.');
        seedAdminUser();
    })
    .catch(err => console.error('MongoDB connection error:', err));

// --- Authentication Middleware ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (e) {
        res.status(400).json({ msg: 'Token is not valid' });
    }
};
const requireRole = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ msg: 'Access denied. Insufficient role.' });
    }
    next();
};

// --- API Endpoints ---
app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });
        const payload = { user: { id: user.id, role: user.role, email: user.email } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, user: payload.user });
        });
    } catch (err) { res.status(500).send('Server error'); }
});

app.get('/api/users', [auth, requireRole(['Admin'])], async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) { res.status(500).send('Server Error'); }
});

app.post('/api/users/create', [auth, requireRole(['Admin'])], async (req, res) => {
    const { email, password, role } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });
        user = new User({ email, password, role });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();
        res.json({ msg: 'User created successfully' });
    } catch (err) { res.status(500).send('Server Error'); }
});

app.delete('/api/users/:id', [auth, requireRole(['Admin'])], async (req, res) => {
    try {
        await User.findByIdAndRemove(req.params.id);
        res.json({ msg: 'User deleted' });
    } catch (err) { res.status(500).send('Server Error'); }
});

app.get('/api/equipment', auth, async (req, res) => {
    try {
        const equipment = await Equipment.find().sort({ createdAt: -1 });
        res.json(equipment);
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post('/api/equipment', [auth, requireRole(['Admin', 'Editor'])], async (req, res) => {
    const newEquipment = new Equipment(req.body);
    try {
        const savedEquipment = await newEquipment.save();
        res.status(201).json(savedEquipment);
    } catch (err) { res.status(400).json({ message: err.message }); }
});

app.put('/api/equipment/:id', [auth, requireRole(['Admin', 'Editor'])], async (req, res) => {
    try {
        const updatedEquipment = await Equipment.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updatedEquipment);
    } catch (err) { res.status(400).json({ message: err.message }); }
});

app.delete('/api/equipment/:id', [auth, requireRole(['Admin'])], async (req, res) => {
    try {
        await Equipment.findByIdAndDelete(req.params.id);
        res.json({ message: 'Equipment deleted successfully' });
    } catch (err) { res.status(500).json({ message: err.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
