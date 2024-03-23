const jwt = require("jsonwebtoken")
const otpGenerator = require("otp-generator");
const crypto = require("crypto")
const User = require("../models/user");
const filterObj = require("../utils/filterObj");
const { promisify } = require("util");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);
exports.register = async (req, res, next) => {
    const { firstName, lastName, email, password } = req.body;
    const filteredBody = filterObj(req.body, "firstName", "lastName", "password", "email");

    const existing_user = await User.findOne({ email: email });

    if (existing_user && existing_user.verified) {
        res.status(400).json({
            status: "error",
            message: "Email is already in use, Please login"
        })
    
    }
    else if (existing_user) {
        await User.findOneAndUpdate({ email: email }, filteredBody, { new: true, validateModifiedOnly: true })
        req.userId = existing_user._id;
        next();
    }
    else {
        const new_user = await User.create(filteredBody);
        req.userId = new_user._id;
        next();
    }


}
exports.sendOtp = async (req, res, next) => {
    const { userId } = req;
    const new_otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false })
    const otp_expiry_time = Date.now() + 10 * 60 * 1000;
    await User.findByIdAndUpdate(userId, {
        otp: new_otp,
        otp_expiry_time
    })

    res.status(200).json({
        status: "success",
        message: "OTP Sent Successfully"
    })
}
exports.verifyOTP = async (req, res, next) => {
    const { email, otp } = req.body;
    const user = await User.findOne({
        email,
        otp_expiry_time: { $gt: Date.now() }
    })

    if (!user) {
        res.status(400).json({
            status: "error",
            message: "Email is Invalid or OTP expired"
        })
        return;
    }

    if (!await user.correctOTP(otp, user.otp)) {
        res.status(400).json({
            status: "error",
            message: "OTP is incorrect"
        })
    }

    user.verified = true;
    user.otp = undefined;

    await user.save({ new: true, validateModifiedOnly: true });

    const token = signToken(userDoc._id);

    res.status(200).json({
        status: "success",
        message: "OTP verified successfully!",
        token
    })
}
exports.login = async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        res.status(400).json({
            status: "error",
            message: "Both email and password are required"
        })
    }

    const userDoc = await User.findOne({ email: email }).select("+password");

    if (!userDoc || !(await userDoc.correctPassword(password, userDoc.password))) {
        res.status(400).json({
            status: "error",
            message: "Email or Password is incorrect"
        })
    }

    const token = signToken(userDoc._id);



    res.status(200).json({
        status: "success",
        message: "Logged in successfully",
        token
    });
}
exports.protect = async (req, res, next) => {
     let token;
     if(req.headers.authorization && req.headers.authorization.startsWith("Bearer")){
         token = req.headers.authorization.split(" ")[1];

     }
     else if(req.cookies.jwt){
         token = req.cookies.jwt;
     }
     else{
        res.status(400).json({
            status: "error",
            message: "You are not logged In! Please login to get access"
        })

        return;
     }
     const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
     const this_user = await User.findById(decoded.userId);
     if(!this_user){
        res.status(400).json({
            status: "error",
            message: "The user doesn't exist",
        })
     }

     if(this_user.changedPasswordAfter(decoded.iat)){
        res.status(400).json({
            status: "error",
            message: "User recently updated password! Please login again"
        })
     }
     req.user = this_user
     next()
}
exports.forgotPassword = async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        res.status(400).json({
            status: "error",
            message: "There is no user with given email address"
        })
    }

    const resetToken = user.createPasswordResetToken();
    const resetURL = `https://tawk.com/auth/reset-password/?code=${resetToken}`
    try {
        res.status(200).json({
            status: "success",
            message: "Reset Password link sent to Email"
        })
    }
    catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        res.status(500).json({
            status: "error",
            message: "There was an error sending the email, Please try again later"
        })
    }
}
exports.resetPassword = async (req, res, next) => {
     const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex")
     const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {$gt: Date.now()}
     })
     if(!user){
        res.status(400).json({
            status: "error",
            message: "Token is Invalid or Expired"
        })
        return;
     }
     user.password = req.body.password;
     user.passwordConfirm = req.body.passwordConfirm;
     user.passwordResetToken = undefined;
     user.passwordResetExpires = undefined;
     await user.save();
     const token = signToken(user._id);
     res.status(200).json({
        status: "success",
        message: "Password Resetted Successfully",  
        token
     })

}