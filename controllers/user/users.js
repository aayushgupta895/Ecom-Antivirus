import dotenv from 'dotenv';
dotenv.config()

import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";


import { db } from "../../models/index.js";
import { sendOtpToEmail } from "../../utils/utils.js";
import asyncErrorHandler from "../../Error/asyncErrorHandler.js";
import ErrorHandler from "../../Error/errorHandler.js";

export const userSignUp = async (req, res, next) => {
    const { name, email, phoneNo, password, city, state } = req.body;
    try {

        // validate Email
        if (!validator.isEmail(email)) throw Error("Invalid Email");

        // check if user exists
        const countExistingUser = await db.User.findAndCountAll({
            where: {
                email,
            }
        })

        if (countExistingUser.count != 0) throw Error("User already exists");

        // validate Phone Number
        if (!validator.isMobilePhone(phoneNo, ["en-IN"])) throw Error("Invalid Phone Number");

        // validate password - password length minimum 6 charachters
        if (password.length < 6) throw Error("Password too short");

        // validate password - password length maximum 20 charachters
        if (password.length > 20) throw Error("Password too long");

        // generating password hash
        const salt = bcrypt.genSaltSync(12);
        const hash = await bcrypt.hash(password, salt);

        // send otp to email
        const otp = await sendOtpToEmail(req, res, next);

        const userDetails = {
            name, email, phoneNo, city, state, password: hash, otp: otp
        }

        const uniqueId = uuidv4();

        // add to redis
        await db.redisClient.set(uniqueId, JSON.stringify(userDetails), {
            "EX": 60 * 3,
        });

        res.status(200).send({
            message: "OTP sent to email",
            otp_token: uniqueId,
        });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const verifyAndRegister = async (req, res) => {
    try {

        const { otp_token, email, otp } = req.body;

        const data = await db.redisClient.get(otp_token)

        if (!data) throw Error("OTP expired");

        const userDetails = JSON.parse(data);

        if (userDetails.email != email) throw Error("Invalid Email");
        if (userDetails.otp != otp) throw Error("Invalid OTP");

        const newUser = await db.User.create({
            name: userDetails.name,
            email: userDetails.email,
            phoneNo: userDetails.phoneNo,
            city: userDetails.city,
            state: userDetails.state,
            password: userDetails.password,
        });

        await db.Cart.create({
            userId: newUser.userId,
        });

        // creating access and refresh tokens
        let accessTokenTime = 1000 * 60 * 60 * 24;
        let refreshTokenTime = 1000 * 60 * 60 * 24 * 7;
        const accessToken = jwt.sign({ userId: newUser.userId }, process.env.USER_ACCESS_TOKEN_SECRET, { expiresIn: String(accessTokenTime) });
        const refreshToken = jwt.sign({ userId: newUser.userId }, process.env.USER_REFRESH_TOKEN_SECRET, { expiresIn: String(refreshTokenTime) });

        // add refresh token to redis
        await db.redisClient.set(newUser.userId, refreshToken, {
            "PX": refreshTokenTime,
        });


        res.status(200)
            .json({
                message: "User Registered",
                userId: newUser.userId,
                name: newUser.name,
                email: newUser.email,
                phoneNo: newUser.phoneNo,
                city: newUser.city,
                state: newUser.state,
                accessToken: accessToken,
                refreshToken: refreshToken,
            });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const userSignIn = async (req, res) => {
    const { email, password } = req.body;
    try {

        // validate Email
        if (!validator.isEmail(email)) throw Error("Invalid Email");

        // check if user exists
        const existingUser = await db.User.findOne({
            where: {
                email,
            }
        });

        if (!existingUser) throw Error("User does not exist");

        // compare passwords
        const match = await bcrypt.compare(password, existingUser.password);

        if (!match) throw Error("Incorrect Password")

        // create access and refresh tokens
        let accessTokenTime = 1000 * 60 * 60 * 24;
        let refreshTokenTime = 1000 * 60 * 60 * 24 * 7;
        const accessToken = jwt.sign({ userId: existingUser.userId }, process.env.USER_ACCESS_TOKEN_SECRET, { expiresIn: String(accessTokenTime) });
        const refreshToken = jwt.sign({ userId: existingUser.userId }, process.env.USER_REFRESH_TOKEN_SECRET, { expiresIn: String(refreshTokenTime) });

        // add refresh token to db
        await db.redisClient.set(existingUser.userId, refreshToken, {
            "PX": refreshTokenTime,
        });

        res
            .status(200)
            .json({
                userId: existingUser.userId,
                name: existingUser.name,
                email: existingUser.email,
                phoneNo: existingUser.phoneNo,
                city: existingUser.city,
                state: existingUser.state,
                accessToken: accessToken,
                refreshToken: refreshToken,
            });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const userRefreshToken = async (req, res) => {
    try {

        const { authorization } = req.headers;

        if (!authorization) {
            return res.status(401).json({ error: "Refresh token required" });
        }

        const refreshToken = authorization.split(" ")[1];

        // check refresh token recieved
        if (!refreshToken) throw Error("Refresh token not found");

        // extract data from jwt
        const data = jwt.verify(refreshToken, process.env.USER_REFRESH_TOKEN_SECRET);
        if (!data.userId) throw Error("Invalid refresh token");

        const existingRefreshToken = await db.redisClient.get(data.userId);
        if (!existingRefreshToken) throw Error("Refresh token expired");
        if (existingRefreshToken !== refreshToken) throw Error("Invalid refresh token");

        // create access and refresh tokens
        let accessTokenTime = 1000 * 60 * 60 * 24;
        let refreshTokenTime = 1000 * 60 * 60 * 24 * 7;
        const accessToken = jwt.sign({ userId: data.userId }, process.env.USER_ACCESS_TOKEN_SECRET, { expiresIn: String(accessTokenTime) });
        const newRefreshToken = jwt.sign({ userId: data.userId }, process.env.USER_REFRESH_TOKEN_SECRET, { expiresIn: String(refreshTokenTime) });

        // add refresh token to redis
        await db.redisClient.set(data.userId, newRefreshToken, {
            "PX": refreshTokenTime,
        });

        res
            .status(200)
            .json({
                accessToken: accessToken,
                refreshToken: newRefreshToken,
            });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}

export const userLogOut = async (req, res) => {
    try {

        const { authorization } = req.headers;

        if (!authorization) {
            return res.status(401).json({ error: "Refresh token required" });
        }

        const refreshToken = authorization.split(" ")[1];

        // check refresh token recieved
        if (!refreshToken) throw Error("Refresh token not found");

        // verify jwt and extract data
        const data = jwt.verify(refreshToken, process.env.USER_REFRESH_TOKEN_SECRET);

        if (!data.userId) throw Error("Invalid refresh token");

        // delete redis token
        await db.redisClient.del(data.userId);

        res
            .status(200)
            .json("Logged out successfully");

    } catch (error) {
        res.status(400).json({ error: error.messsage });
    }
}

export const forgotPassword = async (req, res, next) => {

    const { email } = req.body;
    const otp = await sendOtpToEmail(req, res, next);

    const userDetails = {
        email, otp: otp,
    }

    const uniqueId = uuidv4();

    // add to redis
    await db.redisClient.set(uniqueId, JSON.stringify(userDetails), {
        "EX": 60 * 3,
    });

    res.status(200).json({
        message: "otp sent successfully",
        otp_token: uniqueId
    });

}

export const verifyAndChangePassword = async (req, res, next) => {

    try {

        const { email, otp_token, otp } = req.body;

        const data = await db.redisClient.get(otp_token);

        if (!data) return next(new ErrorHandler("otp expired", 400));

        const userDetails = JSON.parse(data);

        if (userDetails.email != email) return next(new ErrorHandler("Invalid email", 400));
        if (userDetails.otp != otp) return next(new ErrorHandler("Invalid Otp", 400));

        const isChanged = await changePassword(req, res, next);

        if (!isChanged) return next(new ErrorHandler("failed to changed the password", 400));

        res.status(200).json({
            message: "verified successfully and password changed successfully"
        });

    } catch (error) {

        console.log(error);
        res.status(500).json({
            error: "internal server error"
        })

    }

}

export const changePassword = asyncErrorHandler(async (req, res, next) => {

    const { email, newPassword } = req.body;
    const salt = bcrypt.genSaltSync(12);

    const newHash = await bcrypt.hash(newPassword, salt);

    const updatedUser = await db.User.update({ password: newHash }, { where: { email: email } });
    console.log(updatedUser)
    if (updatedUser[0] !== 1) return false;
    return true;

})