import UserModel from '../models/user.model.js';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const generateRefreshToken = async(userId) => {
       const refreshToken = await jwt.sign(
        {id : userId}, 
        process.env.REFRESH_TOKEN_SECRET_KEY, 
        { expiresIn: '24h'}
    );
        
    const updateRefreshToken = await UserModel.findByIdAndUpdate(
        { _id: userId },
        { refresh_token: refreshToken }
    );
        return refreshToken;  
 }

export default generateRefreshToken;
