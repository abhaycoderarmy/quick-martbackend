import UserModel from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import sendEmail from '../config/sendEmail.js';
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';
import generatedAccessToken from '../utils/generatedAccessToken.js';
import generateRefreshToken from '../utils/generateRefreshToken.js';    
import uploadImageClodinary from '../utils/uploadImageToCloudinary.js';
import generateOtp from '../utils/generateOtp.js';
import forgotPasswordTemplate from '../utils/forgetPasswordEmailTemplate.js';
import dotenv from 'dotenv';
dotenv.config();


export const registerUserController = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ 
                message: 'Please Fill All Fields',
                error : true,
                success : false
            });
        }
         
        const userExists = await UserModel.findOne({ email });
        if (userExists) {
            return res.status(400).json({ 
                message: 'User already exists',
                error : true,
                success : false
            });
        }

        const salt = await bcrypt.genSalt(10); 
//Salt is a random value added to the password before hashing to make it more secure. 10 is the number of rounds to generate the salt, higher the number more secure it is but also more time consuming.

        const hashedPassword = await bcrypt.hash(password, salt);

        const payload = {
            name,
            email,
            password : hashedPassword
        }

        const user = await UserModel.create(payload);
        
        const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${user?._id}`;

        const verificationEmail = await sendEmail(
            email,
            'For QuickMart Account Verification',
            verifyEmailTemplate({
                name,
                url: verifyEmailUrl
            })
        );

        if (!verificationEmail) {
            return res.status(500).json({ 
                message: 'Error sending verification email',
                error : true,
                success : false
            });
        }

        return res.status(200).json({   
            message : "User created successfully, Please verify your email",
            data : user,
            error : false,
            success : true
        });

    } catch (error) {
        res.status(500).json({
             message: error.message || error, 
             error : true,
             success : false
        });
    }
}

export const verifyEmailController = async (req, res) => { 
    try {

        const { code } = req.body;
        const user = await UserModel.findById({_id : code});

        if (!user) {
            return res.status(400).json({ 
                message: 'Invalid verification code',
                error : true,
                success : false
            });
        }

        const updatedUser = await UserModel.findByIdAndUpdate(
            { _id: code },
            { verify_email: true }
        );  

        return res.status(200).json({   
            message : "Email verified successfully",
            data : updatedUser,
            error : false,
            success : true
        });
        
    } catch (error) {
        res.status(500).json({
             message: error.message || error, 
             error : true,
             success : false
        });
        
    }
}

export const loginUserController = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                message: 'Please fill all fields',
                error : true,
                success : false
            });
        }

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ 
                message: 'Invalid credentials or User not registered',
                error : true,
                success : false
            });
        }

        if(user.status !== "Active"){
            return res.status(400).json({ 
                message: 'Connect to Admin',
                error : true,
                success : false
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ 
                message: 'Invalid Password',
                error : true,
                success : false
            });
        }

        const accessToken = await generatedAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);


        const updatedUser = await UserModel.findByIdAndUpdate(
            { _id: user._id },
            {last_login_date : new Date()}
        );

        const cookieOptions = {
            httpOnly: true, // This means the cookie cannot be accessed via JavaScript from the browser
            sameSite: 'None', // This allows the cookie to be sent with cross-site requests 
            secure: true // This means the cookie will only be sent over HTTPS connections
        }

        res.cookie('accessToken', accessToken, cookieOptions);
        res.cookie('refreshToken', refreshToken, cookieOptions);

        return res.status(200).json({   
            message : "Login successfully",
            error : false,
            success : true,
            data : {
                accessToken,
                refreshToken
            }
        });

    } catch (error) {
        res.status(500).json({
             message: error.message || error, 
             error : true,
             success : false   
        });        
    }
}

export const getUserDetailsController = async (req, res) => {
    try {
        const userId = req.userId; // coming from auth middleware
        const user = await UserModel.findById(userId).select('-password -refresh_token');
        return res.status(200).json({
            message : "User details fetched successfully",
            error : false,
            success : true,
            data : user
        })
    } catch (error) {
        console.log("error in getUserDetailsController") ;
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export const logoutUserController = async (req, res) => {
    try {
        const userId = req.userId; // coming from auth middleware 

        if (!userId) {
            return res.status(400).json({ 
                message: 'User must be logged in to logout',
                error : true,
                success : false
            });
        }

        const user = await UserModel.findById(userId);

        if (!user || !user.refresh_token) {
            return res.status(400).json({ 
                message: 'User already logged out',
                error : true,
                success : false
            });
        }

        const cookieOptions = {
            httpOnly: true,
            sameSite: 'None',
            secure: true
        }

        res.clearCookie('accessToken', cookieOptions);
        res.clearCookie('refreshToken', cookieOptions);

        await UserModel.findOneAndUpdate(
            { _id: userId },
            { $set: { refresh_token: "" } },
        );

        return res.status(200).json({   
            message : "Logout successfully",
            error : false,
            success : true
        });

    } catch (error) {
        res.status(500).json({
             message: error.message || error, 
             error : true,
             success : false   
        });        
    }
}

export const uploadAvatarController = async (req, res) => {
    try {
       
       const userId = req.userId; // coming from auth middleware

       const image = req.file; // coming from multer middleware

       const upload = await uploadImageClodinary(image);

        const user = await UserModel.findByIdAndUpdate(userId, { avatar: upload.url });

        return res.status(200).json({
            message: 'Avatar uploaded successfully',
            error : false,
            success : true,
            data : {
                _id : userId,
                avatar : upload.url
            }
        }); 
   
    } catch (error) {
        res.status(500).json({
             message: error.message || error, 
             error : true,
             success : false   
        });         
    }
}

export const updateUserDetailsController = async (req, res) => {
    try {

        const userId = req.userId // coming from auth middleware 
        const { name, email, mobile, password } = req.body 

        let hashPassword = ""

        if(password){
            const salt = await bcrypt.genSalt(10)
            hashPassword = await bcrypt.hash(password,salt)
        }

        const updateUser = await UserModel.updateOne({ _id : userId},{
            ...(name && { name : name }),
            ...(email && { email : email }),
            ...(mobile && { mobile : mobile }),
            ...(password && { password : hashPassword })
        })

        return res.json({
            message : "User Details Updated successfully",
            error : false,
            success : true,
            data : updateUser
        })

    } catch (error) {
        console.log("error in updateUserDetailsController") ;
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export const forgotPasswordController = async (req, res) => {
    try {
        
        const { email } = req.body;

        const user = await UserModel.findOne({ email });    
        if (!user) {
            return res.status(400).json({ 
                message: 'Email not found!',
                error : true,
                success : false
            });
        }

        const otp = generateOtp();
        const expireTime = new Date().getTime() + 5 * 60 * 1000; // 5 minutes

        const updatedUser = await UserModel.findByIdAndUpdate(user._id, {
            forgot_password_otp : otp,
            forgot_password_expiry : new Date(expireTime).toISOString()
        })
         
        const forgetpassEmail = await sendEmail(
            email,
            "OTP for forget password of QuickMart",
            forgotPasswordTemplate({
                name: user.name,
                otp: otp
            })
        );

        console.log("OTP sent to your email");

        res.status(200).json({
            message: 'OTP sent to your email',
            error : false,
            success : true
        });

    } catch (error) {
           console.log("error in forgetPasswordController") ;
            return res.status(500).json({
                message : error.message || error,
                error : true,
                success : false
        })       
    }
}

export const verifyForgotPasswordOtpController = async (req, res) => {
    try {

        const { email, otp } = req.body;
        if(!email || !otp){
            return res.status(400).json({
                message : "Please provide email and otp",
                error : true,
                success : false
            })
        }

        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(400).json({ 
                message: 'Email not found!',
                error : true,
                success : false
            });
        }

        const currentTime = new Date().toISOString();  

        if(user.forgot_password_expiry < currentTime){
            return res.status(400).json({
                message : "OTP expired",
                error : true,
                success : false
            })
        }

        if(user.forgot_password_otp !== otp){
            return res.status(400).json({
                message : "Invalid OTP",
                error : true,
                success : false
            })
        }
        
        const updatedUser = await UserModel.findByIdAndUpdate
        (user?._id, {
            forgot_password_otp : "",
            forgot_password_expiry : ""
        })

        return res.status(200).json({
            message : "OTP verified successfully",
            error : false,
            success : true
        })
        
    } catch (error) {
        res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export const resetPasswordController = async (req, res) => {
    try {     
            const { email, newPassword, confirmPassword } = req.body;
            if (!email || !newPassword || !confirmPassword) {
                return res.status(400).json({ 
                    message: 'Please fill all fields email, newPassword, confirmPassword',
                    error : true,
                    success : false
                });
            }
    
            const user = await UserModel.findOne({ email });
            if (!user) {
                return res.status(400).json({ 
                    message: 'Email not found!',
                    error : true,
                    success : false
                });
            }

            if(newPassword !== confirmPassword){
                return res.status(400).json({
                    message : "Password does not match",
                    error : true,
                    success : false
                })
            }
    
            const salt = await bcrypt.genSalt(10);
            const hashPassword = await bcrypt.hash(newPassword, salt);
    
            const updatedUser = await UserModel.findByIdAndUpdate(user._id, {
                password : hashPassword
            })
    
            return res.status(200).json({
                message : "Password reset successfully",
                error : false,
                success : true
            })

    } catch (error) {
        res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export const refreshTokenController = async (req, res) => {
    try {

const refreshToken = req.cookies.refreshToken || req.header?.authorization?.split(" ")[1];

          console.log(refreshToken);

            if(!refreshToken){
                return res.status(400).json({
                    message : "Please provide refresh token",
                    error : true,
                    success : false
                })
            }
        
        const verifyToken = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY);

            if(!verifyToken){
                return res.status(400).json({
                    message : "Invalid refresh token or Token is expired",
                    error : true,
                    success : false
                })
            }
            
            console.log(verifyToken);
             const newAccessToken = await generatedAccessToken(verifyToken.id);

             const cookieOptions = {
                httpOnly: true,
                sameSite: 'None',
                secure: true
            }

            res.cookie('accessToken', newAccessToken, cookieOptions);
            
            res.status(200).json({
                message : "New access token generated successfully",
                error : false,
                success : true,
                data : {
                    accessToken : newAccessToken
                }
            })

    } catch (error) {
        console.log("error in refreshTokenController");
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false,
            data : {
                accessToken : newAccessToken
            }
        });
    }
}

export const getAllUsersController = async (req, res) => {
    try {
        const users = await UserModel.find({}).select('-password -refresh_token');
        return res.status(200).json({
            message : "All users fetched successfully",
            error : false,
            success : true,
            data : users
        })
    } catch (error) {
        console.log("error in getAllUsersController") ;
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export const blockUserController = async (req, res, next) => {
    try {
        const userId = req.userId; // from middleware
        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: 'User not found',
                error: true,
                success: false,
            });
        }
        
    const updatedUser = await UserModel.findByIdAndUpdate(userId, 
        { status: 'Suspended'}, 
        { new: true });
        
        if(updatedUser){
            return res.status(200).json({
                message: 'User blocked successfully',
                error: false,
                success: true,
            });
        }
    } catch (error) {
        return res.status(500).json({
            message: 'Error in validating user',
            error: true,
            success: false,
        });
    }
}