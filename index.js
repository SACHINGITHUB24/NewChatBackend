// // Ultimate Hi Chat Backend - WebSocket → Socket.IO Migration (FIXED)
// const express = require('express');
// const http = require('http');
// const { Server } = require('socket.io');
// const cors = require('cors');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const mongoose = require('mongoose');
// require('dotenv').config();

// // MongoDB Models
// const User = require('./models/User');
// const Message = require('./models/Message');
// const Group = require('./models/Group');

// const app = express();
// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: { origin: "*", methods: ["GET", "POST"] }
// });

// const PORT = process.env.PORT || 3001;
// const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
// const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority';

// // In-memory storage for socket connections and chat rooms
// const wsStorage = {
//   connections: new Map(),
//   chatRooms: new Map(),
//   userSockets: new Map() // userId -> socketId mapping
// };

// // ===== MongoDB Connection =====
// async function connectDB() {
//   try {
//     await mongoose.connect(MONGODB_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     console.log('✅ MongoDB Connected Successfully');
//   } catch (error) {
//     console.error('❌ MongoDB Connection Error:', error.message);
//     process.exit(1);
//   }
// }

// // ===== System Initialization =====
// async function initSystem() {
//   try {
//     // Admin user
//     let adminUser = await User.findOne({ username: 'admin' });
//     if (!adminUser) {
//       adminUser = new User({
//         name: 'Administrator',
//         username: 'admin',
//         email: 'admin@hichat.com',
//         password: await bcrypt.hash('admin123', 12),
//         role: 'admin',
//         status: 'active'
//       });
//       await adminUser.save();
//       console.log('✅ Admin user created');
//     }

//     // Test users
//     const testUsers = [
//       { name: 'John Doe', username: 'john', email: 'john@test.com' },
//       { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
//       { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' }
//     ];
    
//     for (const userData of testUsers) {
//       const existingUser = await User.findOne({ username: userData.username });
//       if (!existingUser) {
//         const user = new User({
//           ...userData,
//           password: await bcrypt.hash('password123', 12),
//           role: 'user',
//           status: 'active'
//         });
//         await user.save();
//         console.log(✅ Test user created: ${userData.username});
//       }
//     }

//     const userCount = await User.countDocuments();
//     console.log(✅ Initialized MongoDB with ${userCount} users);
//   } catch (error) {
//     console.error('❌ Error initializing system:', error);
//   }
// }

// // ===== Middleware =====
// app.use(cors({ origin: "*", credentials: true }));
// app.use(express.json({ limit: '50mb' }));

// // ===== Auth Middleware =====
// const auth = async (req, res, next) => {
//   try {
//     const token = req.header('Authorization')?.replace('Bearer ', '');
//     if (!token) return res.status(401).json({ error: 'No token' });

//     const decoded = jwt.verify(token, JWT_SECRET);
//     const user = await User.findById(decoded.userId);
//     if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

//     req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
//     next();
//   } catch (error) {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// };

// // ===== API Routes =====

// // Health check
// app.get('/api/health', async (req, res) => {
//   try {
//     const userCount = await User.countDocuments();
//     const messageCount = await Message.countDocuments();
//     const groupCount = await Group.countDocuments();
//     res.json({
//       status: 'OK',
//       message: 'Hi Chat Ultimate Backend with MongoDB & Socket.IO',
//       version: '2.2.0',
//       database: 'MongoDB Connected',
//       users: userCount,
//       messages: messageCount,
//       groups: groupCount,
//       connections: wsStorage.connections.size,
//       timestamp: new Date().toISOString()
//     });
//   } catch (error) {
//     res.status(500).json({ status: 'ERROR', message: 'Database connection failed', error: error.message });
//   }
// });

// // Login
// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await User.findOne({ 
//       $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] 
//     });
//     if (!user) return res.status(401).json({ error: 'Invalid credentials' });

//     const isValidPassword = await bcrypt.compare(password, user.password);
//     if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

//     user.isOnline = true;
//     user.lastSeen = new Date();
//     await user.save();

//     const token = jwt.sign(
//       { userId: user._id, username: user.username, role: user.role }, 
//       JWT_SECRET, 
//       { expiresIn: '30d' }
//     );
    
//     res.json({ 
//       success: true, 
//       token, 
//       user: { 
//         id: user._id, 
//         name: user.name, 
//         username: user.username, 
//         email: user.email, 
//         role: user.role, 
//         profilePic: user.profilePic, 
//         isOnline: user.isOnline 
//       } 
//     });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ error: 'Login failed' });
//   }
// });

// // Fetch all users
// app.get('/api/users', auth, async (req, res) => {
//   try {
//     const users = await User.find({}, '-password').lean();
//     res.json({ success: true, users });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch users' });
//   }
// });

// // Get messages for a chat
// app.get('/api/messages/:chatId', auth, async (req, res) => {
//   try {
//     const { chatId } = req.params;
//     const messages = await Message.find({ chatId })
//       .populate('senderId', 'name username profilePic')
//       .sort({ timestamp: 1 })
//       .limit(100)
//       .lean();
    
//     res.json({ success: true, messages });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch messages' });
//   }
// });

// // Create or get chat
// app.post('/api/chats', auth, async (req, res) => {
//   try {
//     const { participants, type = 'direct' } = req.body;
//     if (!participants || participants.length < 2) {
//       return res.status(400).json({ error: 'Need at least 2 participants' });
//     }

//     // For direct chats, create a consistent chatId
//     let chatId;
//     if (type === 'direct') {
//       const sortedParticipants = participants.sort();
//       chatId = direct_${sortedParticipants.join('_')};
//     } else {
//       chatId = group_${Date.now()}_${Math.random().toString(36).substr(2, 9)};
//     }

//     res.json({ success: true, chatId, participants, type });
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to create chat' });
//   }
// });

// // ===== Socket.IO Event Handlers =====
// io.on("connection", (socket) => {
//   console.log("🔌 Socket.IO connected:", socket.id);
//   let userId = null;

//   // User connection
//   socket.on("user_connected", async (data) => {
//     try {
//       userId = data.userId;
//       wsStorage.connections.set(userId, socket);
//       wsStorage.userSockets.set(socket.id, userId);

//       await User.findByIdAndUpdate(userId, { 
//         isOnline: true, 
//         lastSeen: new Date() 
//       });
      
//       socket.emit("connected", { userId });
//       console.log(👤 User connected: ${data.username} (${userId}));
//     } catch (error) {
//       console.error('Error in user_connected:', error);
//     }
//   });

//   // Join chat room
//   socket.on("join_chat", (data) => {
//     try {
//       const { chatId } = data;
//       socket.join(chatId);
      
//       if (!wsStorage.chatRooms.has(chatId)) {
//         wsStorage.chatRooms.set(chatId, new Set());
//       }
//       wsStorage.chatRooms.get(chatId).add(userId);
      
//       socket.emit("chat_joined", { chatId });
//       console.log(💬 User ${userId} joined chat: ${chatId});
//     } catch (error) {
//       console.error('Error in join_chat:', error);
//     }
//   });

//   // Handle messages
//   socket.on("message", async (msg) => {
//     try {
//       await handleWSMessage(msg, userId, socket);
//     } catch (error) {
//       console.error('Error handling message:', error);
//     }
//   });

//   // Typing indicators
//   socket.on("typing", (msg) => {
//     try {
//       socket.to(msg.chatId).emit("typing", { 
//         username: msg.username, 
//         chatId: msg.chatId,
//         userId: userId
//       });
//     } catch (error) {
//       console.error('Error in typing:', error);
//     }
//   });

//   // WebRTC signaling
//   socket.on("webrtc-signal", (msg) => {
//     try {
//       handleWebRTCSignal(msg, userId);
//     } catch (error) {
//       console.error('Error in webrtc-signal:', error);
//     }
//   });

//   // Disconnect handler
//   socket.on("disconnect", async () => {
//     try {
//       if (userId) {
//         wsStorage.connections.delete(userId);
//         wsStorage.userSockets.delete(socket.id);
        
//         await User.findByIdAndUpdate(userId, { 
//           isOnline: false, 
//           lastSeen: new Date() 
//         });
        
//         console.log(🔌 User ${userId} disconnected);
//       }
//     } catch (error) {
//       console.error('Error in disconnect:', error);
//     }
//   });
// });

// // ===== Message Handler =====
// async function handleWSMessage(msg, senderId, socket) {
//   try {
//     const { chatId, message, type = 'text', metadata = {} } = msg;
    
//     if (!chatId || !message || !senderId) {
//       console.error('Invalid message data:', { chatId, message, senderId });
//       return;
//     }

//     // Save message to MongoDB
//     const newMessage = new Message({
//       chatId,
//       senderId,
//       text: message,
//       type,
//       metadata,
//       timestamp: new Date()
//     });
    
//     await newMessage.save();
    
//     // Populate sender info for broadcasting
//     await newMessage.populate('senderId', 'name username profilePic');
    
//     const messageData = {
//       type: 'new_message',
//       id: newMessage._id,
//       chatId: newMessage.chatId,
//       senderId: newMessage.senderId,
//       content: newMessage.text,
//       messageType: newMessage.type,
//       timestamp: newMessage.timestamp,
//       metadata: newMessage.metadata
//     };

//     // Broadcast to chat room
//     socket.to(chatId).emit('new_message', messageData);
    
//     console.log(📨 Message saved and broadcast: ${chatId});
//   } catch (error) {
//     console.error('Error in handleWSMessage:', error);
//   }
// }

// // ===== Broadcast Functions =====
// function broadcastToChat(chatId, message, excludeUserId = null) {
//   try {
//     const participants = wsStorage.chatRooms.get(chatId);
//     if (participants) {
//       participants.forEach(uid => {
//         if (uid !== excludeUserId) {
//           const sock = wsStorage.connections.get(uid);
//           if (sock) {
//             sock.emit(message.type || 'message', message);
//           }
//         }
//       });
//     }
//   } catch (error) {
//     console.error('Error in broadcastToChat:', error);
//   }
// }

// function broadcastToUser(userId, message) {
//   try {
//     const sock = wsStorage.connections.get(userId);
//     if (sock) {
//       sock.emit(message.type || 'message', message);
//     }
//   } catch (error) {
//     console.error('Error in broadcastToUser:', error);
//   }
// }

// // ===== WebRTC Signal Handler =====
// function handleWebRTCSignal(msg, fromUserId) {
//   try {
//     const { targetUserId, signal, callId, type } = msg;
    
//     const signalData = {
//       type: 'webrtc-signal',
//       signal,
//       callId,
//       fromUserId,
//       signalType: type
//     };
    
//     broadcastToUser(targetUserId, signalData);
//     console.log(📞 WebRTC signal from ${fromUserId} to ${targetUserId});
//   } catch (error) {
//     console.error('Error in handleWebRTCSignal:', error);
//   }
// }

// // ===== Error Handling =====
// process.on('uncaughtException', (error) => {
//   console.error('Uncaught Exception:', error);
// });

// process.on('unhandledRejection', (error) => {
//   console.error('Unhandled Rejection:', error);
// });

// // ===== Start Server =====
// async function startServer() {
//   try {
//     await connectDB();
//     await initSystem();
    
//     server.listen(PORT, () => {
//       console.log(🚀 Hi Chat Ultimate Backend with MongoDB & Socket.IO running on port ${PORT});
//       console.log(📡 Socket.IO server ready);
//       console.log(🌐 API: http://localhost:${PORT}/api);
//       console.log(💾 MongoDB: Connected and initialized);
//       console.log(🔑 Admin: admin/admin123);
//     });
//   } catch (error) {
//     console.error('❌ Failed to start server:', error);
//     process.exit(1);
//   }
// }

// startServer();

// module.exports = { app, server, io };




// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const { connectDB } = require('./config/database');
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData';
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';

(async () => {
  try {
    await connectDB(MONGODB_URI);
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
})();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET","POST","PUT","DELETE"] }
});

// create uploads folder
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));

// ---------- helper: auth middleware ----------
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { userId: payload.userId, username: payload.username, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Routes: health, login, users, messages, groups, upload ----------
app.get('/api/health', async (req, res) => {
  try {
    const users = await User.countDocuments();
    const messages = await Message.countDocuments();
    const groups = await Group.countDocuments();
    res.json({ status: 'OK', database: 'Connected', users, messages, groups, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: 'ERROR', error: err.message });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const user = await User.findOne({ $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user._id, username: user.username, name: user.name, profilePic: user.profilePic, role: user.role, isOnline: user.isOnline } });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// get users
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const users = await User.find({}, '-password').lean();
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// upload file
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ success: true, url, originalname: req.file.originalname, filename: req.file.filename, size: req.file.size });
});

// get messages
app.get('/api/messages/:chatId', authMiddleware, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { limit = 100 } = req.query;
    const msgs = await Message.find({ chatId }).populate('senderId', 'name username profilePic').sort({ timestamp: 1 }).limit(Number(limit)).lean();
    res.json({ success: true, messages: msgs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// create group
app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    const { name, description, members = [] } = req.body;
    const group = new Group({ name, description, createdBy: req.user.userId, members: [req.user.userId, ...members], admins: [req.user.userId] });
    await group.save();
    await group.populate('members', 'name username profilePic');
    res.status(201).json(group);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// get groups for user
app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.userId }).populate('members', 'name username profilePic isOnline').populate('createdBy', 'name username').sort({ updatedAt: -1 }).lean();
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch groups' });
  }
});

// ---------- Socket.IO real-time ----------

// in-memory maps (userId -> socket)
const userSockets = new Map(); // userId -> socket
const socketUsers = new Map();  // socket.id -> userId
const chatRooms = new Map();    // chatId -> Set(userId)

io.use((socket, next) => {
  // Allow token in handshake: socket = io(backend, { auth: { token }})
  const token = socket.handshake.auth?.token;
  if (!token) return next(); // still allow connection; we'll accept user_connected event too
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.authUser = { userId: payload.userId, username: payload.username, role: payload.role };
    return next();
  } catch (err) {
    console.warn('Socket auth failed', err.message);
    return next(); // allow connection without auth (client can emit user_connected)
  }
});

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);

  // If authenticated at handshake, register
  if (socket.authUser) {
    const uid = String(socket.authUser.userId);
    userSockets.set(uid, socket);
    socketUsers.set(socket.id, uid);
    User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() }).catch(()=>{});
    socket.emit('connected', { userId: uid });
    console.log('Registered from handshake', uid);
  }

  // Also accept explicit user_connected for older clients
  socket.on('user_connected', async (data) => {
    try {
      if (!data || !data.userId) return;
      const uid = String(data.userId);
      userSockets.set(uid, socket);
      socketUsers.set(socket.id, uid);
      await User.findByIdAndUpdate(uid, { isOnline: true, lastSeen: new Date() });
      socket.emit('connected', { userId: uid });
      console.log('Registered via event', uid);
    } catch (err) {
      console.error('user_connected handler error', err);
    }
  });

  // join chat room
  socket.on('join_chat', async (data) => {
    try {
      const chatId = data?.chatId;
      const uid = socketUsers.get(socket.id);
      if (!chatId || !uid) return socket.emit('error', { message: 'join_chat requires chatId and authenticated user' });
      await socket.join(chatId);
      if (!chatRooms.has(chatId)) chatRooms.set(chatId, new Set());
      chatRooms.get(chatId).add(uid);
      socket.emit('chat_joined', { chatId });
      console.log(`User ${uid} joined chat ${chatId}`);
    } catch (err) {
      console.error('join_chat error', err);
    }
  });

  // leave chat
  socket.on('leave_chat', (data) => {
    try {
      const chatId = data?.chatId;
      const uid = socketUsers.get(socket.id);
      if (!chatId || !uid) return;
      socket.leave(chatId);
      if (chatRooms.has(chatId)) {
        chatRooms.get(chatId).delete(uid);
      }
      socket.emit('chat_left', { chatId });
    } catch (err) {
      console.error('leave_chat error', err);
    }
  });

  // message handler: expects { chatId, message, type, metadata }
  socket.on('message', async (msg) => {
    try {
      const uid = socketUsers.get(socket.id);
      // fallback to handshake user if set
      if (!uid && socket.authUser) uid = String(socket.authUser.userId);
      if (!uid) return socket.emit('error', { message: 'Not authenticated' });

      const chatId = msg?.chatId;
      const text = msg?.message || msg?.text || msg?.content;
      const type = msg?.type || 'text';
      const metadata = msg?.metadata || {};

      if (!chatId || !text) return socket.emit('error', { message: 'chatId and message required' });

      // Save to DB
      const mongoose = require('mongoose');
      const saved = new Message({
        chatId,
        senderId: mongoose.Types.ObjectId(uid),
        text,
        type,
        metadata,
        timestamp: new Date()
      });

      await saved.save();
      await saved.populate('senderId', 'name username profilePic');

      // Build broadcast payload
      const payload = {
        type: 'new_message',
        id: saved._id,
        chatId: saved.chatId,
        senderId: { _id: saved.senderId._id, username: saved.senderId.username, name: saved.senderId.name, profilePic: saved.senderId.profilePic },
        content: saved.text,
        messageType: saved.type,
        timestamp: saved.timestamp
      };

      // Broadcast to everyone in the room (including sender)
      io.to(chatId).emit('new_message', payload);

      console.log('Message saved and broadcast to', chatId);
    } catch (err) {
      console.error('message handler error', err);
      socket.emit('error', { message: 'Failed to process message' });
    }
  });

  // typing indicator
  socket.on('typing', (data) => {
    try {
      const chatId = data?.chatId;
      const uid = socketUsers.get(socket.id);
      const username = data?.username || (socket.authUser?.username);
      if (!chatId) return;
      socket.to(chatId).emit('typing', { chatId, userId: uid, username, isTyping: data?.isTyping ?? true });
    } catch (err) {
      console.error('typing error', err);
    }
  });

  // WebRTC signaling forwarding:
  // client sends { targetUserId, callId, type: 'offer'|'answer'|'ice'|'end', signal }
  socket.on('webrtc-signal', (msg) => {
    try {
      const uid = socketUsers.get(socket.id) || (socket.authUser && String(socket.authUser.userId));
      if (!uid) return;
      const target = msg?.targetUserId;
      const targetSocket = userSockets.get(String(target));
      const payload = {
        fromUserId: uid,
        callId: msg?.callId,
        signal: msg?.signal,
        signalType: msg?.type // 'offer'|'answer'|'ice'|'end'
      };
      if (targetSocket) targetSocket.emit('webrtc-signal', payload);
    } catch (err) {
      console.error('webrtc-signal error', err);
    }
  });

  // disconnect
  socket.on('disconnect', async () => {
    try {
      const uid = socketUsers.get(socket.id);
      if (uid) {
        userSockets.delete(uid);
        socketUsers.delete(socket.id);
        await User.findByIdAndUpdate(uid, { isOnline: false, lastSeen: new Date() });
        console.log('User disconnected', uid);
      } else {
        console.log('Socket disconnected (no user)', socket.id);
      }
    } catch (err) {
      console.error('disconnect error', err);
    }
  });
});

// ------- Init helper: create admin + test users if missing -------
async function initDefaults() {
  try {
    const admin = await User.findOne({ username: 'admin' });
    if (!admin) {
      const u = new User({ username: 'admin', name: 'Administrator', email: 'admin@hichat.com', password: await bcrypt.hash('admin123', 12), role: 'admin' });
      await u.save();
      console.log('Created admin');
    }
    const testUsers = ['john','jane','bob'];
    for (const uname of testUsers) {
      let u = await User.findOne({ username: uname });
      if (!u) {
        u = new User({ username: uname, name: uname.charAt(0).toUpperCase() + uname.slice(1), email: `${uname}@test.com`, password: await bcrypt.hash('password123', 12), role: 'user' });
        await u.save();
        console.log('Created user', uname);
      }
    }
  } catch (err) {
    console.error('initDefaults error', err);
  }
}
initDefaults().catch(()=>{});

// serve test UI
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.render('test', { backendUrl: `http://localhost:${PORT}` });
});

// start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
