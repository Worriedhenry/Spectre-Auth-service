const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const app = express();
require('dotenv').config();
app.use(cors({
  origin: '*' ,
  methods: 'GET,POST,PUT,DELETE',
  allowedHeaders: 'Content-Type,Authorization' 

}));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB)
  .then(() => {
    console.log('Connected to DB');
  })
  .catch(err => {
    console.log(err);
  });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());



app.get("/", (req, res) => {
    res.status(200).send("Connected")
  })

const Auth=require('./Authorisation')
app.use('/', Auth)

app.listen(5002, () => {
    console.log("Server running on port 5002")
})  
