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





// Ultimate Hi Chat Backend - WebSocket → Socket.IO Migration (FIXED)
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
require('dotenv').config();

// MongoDB Models
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'hi-chat-ultimate-secret-2024';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority';

// In-memory storage for socket connections and chat rooms
const wsStorage = {
  connections: new Map(),
  chatRooms: new Map(),
  userSockets: new Map() // userId -> socketId mapping
};

// ===== MongoDB Connection =====
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB Connected Successfully');
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    process.exit(1);
  }
}

// ===== System Initialization =====
async function initSystem() {
  try {
    // Admin user
    let adminUser = await User.findOne({ username: 'admin' });
    if (!adminUser) {
      adminUser = new User({
        name: 'Administrator',
        username: 'admin',
        email: 'admin@hichat.com',
        password: await bcrypt.hash('admin123', 12),
        role: 'admin',
        status: 'active'
      });
      await adminUser.save();
      console.log('✅ Admin user created');
    }

    // Test users
    const testUsers = [
      { name: 'John Doe', username: 'john', email: 'john@test.com' },
      { name: 'Jane Smith', username: 'jane', email: 'jane@test.com' },
      { name: 'Bob Wilson', username: 'bob', email: 'bob@test.com' }
    ];
    
    for (const userData of testUsers) {
      const existingUser = await User.findOne({ username: userData.username });
      if (!existingUser) {
        const user = new User({
          ...userData,
          password: await bcrypt.hash('password123', 12),
          role: 'user',
          status: 'active'
        });
        await user.save();
        console.log(`✅ Test user created: ${userData.username}`);
      }
    }

    const userCount = await User.countDocuments();
    console.log(`✅ Initialized MongoDB with ${userCount} users`);
  } catch (error) {
    console.error('❌ Error initializing system:', error);
  }
}

// ===== Middleware =====
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: '50mb' }));

// ===== Auth Middleware =====
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.status !== 'active') return res.status(401).json({ error: 'Invalid user' });

    req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== API Routes =====

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const messageCount = await Message.countDocuments();
    const groupCount = await Group.countDocuments();
    res.json({
      status: 'OK',
      message: 'Hi Chat Ultimate Backend with MongoDB & Socket.IO',
      version: '2.2.0',
      database: 'MongoDB Connected',
      users: userCount,
      messages: messageCount,
      groups: groupCount,
      connections: wsStorage.connections.size,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: 'Database connection failed', error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ 
      $or: [{ username: username.toLowerCase() }, { email: username.toLowerCase() }] 
    });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '30d' }
    );
    
    res.json({ 
      success: true, 
      token, 
      user: { 
        id: user._id, 
        name: user.name, 
        username: user.username, 
        email: user.email, 
        role: user.role, 
        profilePic: user.profilePic, 
        isOnline: user.isOnline 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Fetch all users
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({}, '-password').lean();
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get messages for a chat
app.get('/api/messages/:chatId', auth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const messages = await Message.find({ chatId })
      .populate('senderId', 'name username profilePic')
      .sort({ timestamp: 1 })
      .limit(100)
      .lean();
    
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Create or get chat
app.post('/api/chats', auth, async (req, res) => {
  try {
    const { participants, type = 'direct' } = req.body;
    if (!participants || participants.length < 2) {
      return res.status(400).json({ error: 'Need at least 2 participants' });
    }

    // For direct chats, create a consistent chatId
    let chatId;
    if (type === 'direct') {
      const sortedParticipants = participants.sort();
      chatId = `direct_${sortedParticipants.join('_')}`;
    } else {
      chatId = `group_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    res.json({ success: true, chatId, participants, type });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// ===== Socket.IO Event Handlers =====
io.on("connection", (socket) => {
  console.log("🔌 Socket.IO connected:", socket.id);
  let userId = null;

  // User connection
  socket.on("user_connected", async (data) => {
    try {
      userId = data.userId;
      wsStorage.connections.set(userId, socket);
      wsStorage.userSockets.set(socket.id, userId);

      await User.findByIdAndUpdate(userId, { 
        isOnline: true, 
        lastSeen: new Date() 
      });
      
      socket.emit("connected", { userId });
      console.log(`👤 User connected: ${data.username} (${userId})`);
    } catch (error) {
      console.error('Error in user_connected:', error);
    }
  });

  // Join chat room
  socket.on("join_chat", (data) => {
    try {
      const { chatId } = data;
      socket.join(chatId);
      
      if (!wsStorage.chatRooms.has(chatId)) {
        wsStorage.chatRooms.set(chatId, new Set());
      }
      wsStorage.chatRooms.get(chatId).add(userId);
      
      socket.emit("chat_joined", { chatId });
      console.log(`💬 User ${userId} joined chat: ${chatId}`);
    } catch (error) {
      console.error('Error in join_chat:', error);
    }
  });

  // Handle messages
  socket.on("message", async (msg) => {
    try {
      await handleWSMessage(msg, userId, socket);
    } catch (error) {
      console.error('Error handling message:', error);
    }
  });

  // Typing indicators
  socket.on("typing", (msg) => {
    try {
      socket.to(msg.chatId).emit("typing", { 
        username: msg.username, 
        chatId: msg.chatId,
        userId: userId
      });
    } catch (error) {
      console.error('Error in typing:', error);
    }
  });

  // WebRTC signaling
  socket.on("webrtc-signal", (msg) => {
    try {
      handleWebRTCSignal(msg, userId);
    } catch (error) {
      console.error('Error in webrtc-signal:', error);
    }
  });

  // Disconnect handler
  socket.on("disconnect", async () => {
    try {
      if (userId) {
        wsStorage.connections.delete(userId);
        wsStorage.userSockets.delete(socket.id);
        
        await User.findByIdAndUpdate(userId, { 
          isOnline: false, 
          lastSeen: new Date() 
        });
        
        console.log(`🔌 User ${userId} disconnected`);
      }
    } catch (error) {
      console.error('Error in disconnect:', error);
    }
  });
});

// ===== Message Handler =====
async function handleWSMessage(msg, senderId, socket) {
  try {
    const { chatId, message, type = 'text', metadata = {} } = msg;
    
    if (!chatId || !message || !senderId) {
      console.error('Invalid message data:', { chatId, message, senderId });
      return;
    }

    // Save message to MongoDB
    const newMessage = new Message({
      chatId,
      senderId,
      text: message,
      type,
      metadata,
      timestamp: new Date()
    });
    
    await newMessage.save();
    
    // Populate sender info for broadcasting
    await newMessage.populate('senderId', 'name username profilePic');
    
    const messageData = {
      type: 'new_message',
      id: newMessage._id,
      chatId: newMessage.chatId,
      senderId: newMessage.senderId,
      content: newMessage.text,
      messageType: newMessage.type,
      timestamp: newMessage.timestamp,
      metadata: newMessage.metadata
    };

    // Broadcast to chat room
    socket.to(chatId).emit('new_message', messageData);
    
    console.log(`📨 Message saved and broadcast: ${chatId}`);
  } catch (error) {
    console.error('Error in handleWSMessage:', error);
  }
}

// ===== Broadcast Functions =====
function broadcastToChat(chatId, message, excludeUserId = null) {
  try {
    const participants = wsStorage.chatRooms.get(chatId);
    if (participants) {
      participants.forEach(uid => {
        if (uid !== excludeUserId) {
          const sock = wsStorage.connections.get(uid);
          if (sock) {
            sock.emit(message.type || 'message', message);
          }
        }
      });
    }
  } catch (error) {
    console.error('Error in broadcastToChat:', error);
  }
}

function broadcastToUser(userId, message) {
  try {
    const sock = wsStorage.connections.get(userId);
    if (sock) {
      sock.emit(message.type || 'message', message);
    }
  } catch (error) {
    console.error('Error in broadcastToUser:', error);
  }
}

// ===== WebRTC Signal Handler =====
function handleWebRTCSignal(msg, fromUserId) {
  try {
    const { targetUserId, signal, callId, type } = msg;
    
    const signalData = {
      type: 'webrtc-signal',
      signal,
      callId,
      fromUserId,
      signalType: type
    };
    
    broadcastToUser(targetUserId, signalData);
    console.log(`📞 WebRTC signal from ${fromUserId} to ${targetUserId}`);
  } catch (error) {
    console.error('Error in handleWebRTCSignal:', error);
  }
}

// ===== Error Handling =====
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled Rejection:', error);
});

// ===== Start Server =====
async function startServer() {
  try {
    await connectDB();
    await initSystem();
    
    server.listen(PORT, () => {
      console.log(`🚀 Hi Chat Ultimate Backend with MongoDB & Socket.IO running on port ${PORT}`);
      console.log(`📡 Socket.IO server ready`);
      console.log(`🌐 API: http://localhost:${PORT}/api`);
      console.log(`💾 MongoDB: Connected and initialized`);
      console.log(`🔑 Admin: admin/admin123`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = { app, server, io };

