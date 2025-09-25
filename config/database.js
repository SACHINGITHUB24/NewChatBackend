// const mongoose = require('mongoose');

// const connectDB = async () => {
//   try {
//     const conn = await mongoose.connect(process.env.MONGODB_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });

//     console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
//   } catch (error) {
//     console.error('❌ MongoDB connection error:', error.message);
//     process.exit(1);
//   }
// };

// const testConnection = async () => {
//   try {
//     await mongoose.connection.db.admin().ping();
//     return true;
//   } catch (error) {
//     console.error('Database ping failed:', error);
//     return false;
//   }
// };

// module.exports = { connectDB, testConnection };





const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
};

const testConnection = async () => {
  try {
    if (mongoose.connection.readyState !== 1) {
      console.log('MongoDB not connected yet.');
      return false;
    }
    await mongoose.connection.db.admin().ping();
    console.log('✅ Database ping successful');
    return true;
  } catch (error) {
    console.error('Database ping failed:', error);
    return false;
  }
};

module.exports = { connectDB, testConnection };

