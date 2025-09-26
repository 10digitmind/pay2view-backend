const express = require('express');
const app = express();
const groute = require('./Route/Groutes')
const PORT = 5000;
require('dotenv').config();

const mongoose = require('mongoose');
const cors = require('cors');


app.use(express.json());
app.use(express.urlencoded({ extended: true })); 
const allowedOrigins = [
  'https://pay2view.vercel.app',
  'http://localhost:3000',
'https://pay2view-backend.onrender.com'

];
app.use(cors({
  origin: allowedOrigins,
  credentials: true, // if you need to send cookies or auth headers
}));
app.use(groute)

mongoose
  .connect(process.env.MONGO_URL) 
  
  .then(() => {
    console.log('connected the to database')
  
    app.listen(PORT, () => {
      console.log(`HTTPS server running on https://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.log(error);
    console.error("Database connection error:", error.message);
  });