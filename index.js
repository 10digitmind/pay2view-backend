

const express = require('express');
const app = express();
const groute = require('../backend/Route/Groutes')
const PORT = 5000;
require('dotenv').config();

const mongoose = require('mongoose');
const cors = require('cors');


app.use(express.json());
app.use(express.urlencoded({ extended: true })); 
app.use(cors({
  origin: process.env.CLIENT_URL || '*'
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