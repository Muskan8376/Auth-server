import mongoose, { connect } from "mongoose"

mongoose.connection.on('connected', ()=>console.log("Database connected"))

const connectDB = async()=>{
    await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth`)
}

export  default connectDB;