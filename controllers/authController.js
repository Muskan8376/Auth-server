import bcrypt  from "bcryptjs";
import jwt from "jsonwebtoken"
import userModel from "../Models/userModel.js";
import transporter from "../config/nodemailer.js";
import mongoose from 'mongoose';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";



export const register = async(req,res)=>{
    const { name, email, password } = req.body;

    if(!name || !email || !password){
        return res.json({
            success: false,
            message: "missing details "
        })

    } 
    try {
        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({success : false , message : "User already exists"});
        }

        
        const hashedPassword = await bcrypt.hash(password,10);
        
        const user = new userModel({name, email, password:hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'? 'none' : 'strict',
            maxAge : 7*24*60*60*1000
        });
        // return res.json({success: true});
    

        // sending welcome email

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'welcome to MERN-STACK',
            text: `Welcome toMERN-Stack website . Your account has been created with email id:${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true});

        
    } catch (error) {
        res.json({success:false, message: error.message})
        
    }

 }

 //  logging the user 

 export const login = async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      return res.json({ success: false, message: 'Email and password are required' });
    }
  
    try {
      const user = await userModel.findOne({ email });
  
      if (!user) {
        return res.json({ success: false, message: 'Invalid email' });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
  
      if (!isMatch) {
        return res.json({ success: false, message: 'Invalid password' });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  
      res.cookie('token', token, {
        httpOnly: true,
        secure: true,         // ✅ Always true for HTTPS (Vercel)
        sameSite: 'None',     // ✅ Required for cross-origin cookies
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
  
      return res.json({ success: true });
  
    } catch (error) {
      return res.json({ success: false, message: error.message });
    }
  };
  


 // for logout 

 export  const logout = async(req,res)=>{
    try { 
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'? 'none' : 'strict'

        })
         return res.json({success:true, message: "Logged Out"})
        
    } catch (error) {
        return res.json({success: false, message: error.message} );
    }
 }

 

// Send verification otp to the  user email

export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, message: "userId is required" });
        }

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid userId format" });
        }

        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.status(400).json({ success: false, message: "Account already verified" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); 

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; 

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP is ${otp}. Verify your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        };

        await transporter.sendMail(mailOption);

        res.status(200).json({ success: true, message: 'Verification OTP sent to email' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};


// Verify the Email using the OTP

export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.status(400).json({ success: false, message: "Missing details" });
    }

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ success: false, message: "Invalid userId format" });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (!user.verifyOtp || user.verifyOtp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: 'OTP expired' });
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;
        await user.save();

        return res.status(200).json({ success: true, message: 'Email verified successfully' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};


// //check if  user is  authenticated

// export const isAuthenticated = async(req,res)=>{
//     try {
//         return res.json({success: true});
//     } catch (error) {
//         res.json({success: false, message:error.message});
        
//     }

// }

export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true, user: req.user });  
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};


// Send Password Reset OTP

export const sendResetOtp = async(req,res)=>{
    const {email} = req.body;
    if(!email){
        return res.json({success: false, message: 'Email is required '})
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: 'user not found '})
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000)); 

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() +15 * 60 * 1000; 

        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP resetting your password is ${otp}. Use this otp to procedd with resetting Your Password. `,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        };

        await transporter.sendMail(mailOption);

        return res.json({ success: true , message: 'OTP sent to your email.'})
        
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}


export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP, and new password are required' });
    }

    try {
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.json({ success: false, message: 'user not found' });
        }

        if (!user.resetOtp || user.resetOtp !== String(otp)) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired' });
        }

        if (newPassword.length < 6) {
            return res.json({ success: false, message: 'Password must be at least 6 characters long' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: 'Password has been reset successfully' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

