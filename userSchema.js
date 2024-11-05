const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const userSchema = new Schema({
    username: {
        type: String,
        required: [true, 'Please add username'],
        unique: [true, 'Username already exists']
    },
    fullname:{
        type: String,

     },
    email: {
        type: String,
        required: [true, 'Please add an email'],
        unique: [true, 'Email already exists']
    },
    phone:{
        type:Number,
        // required: [true, 'Please add a phone number'],
        min: 10,
        unique: [true, 'Phone number already exists']
        
    },
    password: {
        type: String,
        // required: [true, 'Please add a password']
    },
    about:{
        type: String,
        default: "Hey, I am using Tailwind+React"
    },
    role: {
        type: String,
        default: "user"
    },
    location: {
        type:Array,
        default:[null,null,null,null,null]
    },
    services:{
        type:Array,
        ref: 'services',
        default: []
    },
    reviews:{
        type:Array,
        default: []
    },
    tasks:[
        {
            type: Schema.Types.ObjectId,
            ref: 'task',
            default: []
        }
    ],
    proposals:[
        {
            type: Schema.Types.ObjectId,
            ref:'task',
            default:[]
        }],
    googleLogin: {
        type: Boolean,
        default: false
    },
    profilePic: {
        type: String,
        default: "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png",
        // https://res.cloudinary.com/drmxw2cme/image/upload/v1711689273/SPECTRE_rllwmd.png
    },
    profileTags: {
        type: Array,
        default: []
    },
    avgResponseTime: {
        type: String,
        default: 0
    },
    avgRating: {
        type: Number,
        default: 0
    },
    education: {
        type: Array,
        default: []
    },
    educationCount: {
        type: Number,
        default: 0
    },
    achievements: {
        type: Array,
        default: []
    },
    payment: {
        type: Array,
        default: []
    },
    socials:{
        type: Array,
        default: []
    },
    personalSite:{
        type: String,
        default: ""
    },
    workHistory:{
        type: Array,
        default: []
    },
    skills:{
        type: Array,
        default: []
    },
    abandonedProposals: {
        type: Number,
        default: 0
    },
    completedProposals: {
        type: Number,
        default: 0
    },
    chatRooms:{
        type: Array,
        default: [],
        ref: 'serviceProposal'
    }
}, { timestamps: true })

module.exports = mongoose.model('Users', userSchema)    