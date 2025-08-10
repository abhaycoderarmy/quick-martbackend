const generateOtp = () => {
    return Math.floor(Math.random() * 900000) + 100000; // 6 digit OTP from 100000 to 999999
}

export default generateOtp;