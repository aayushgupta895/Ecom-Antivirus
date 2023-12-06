import dotenv from "dotenv";
dotenv.config();

import { db } from "../models/index.js"

import jwt from "jsonwebtoken";

const requireUserAuth = async (req, res, next) => {

    const { authorization } = req.headers;
    if (!authorization) {
        return res.status(401).json({ error: "Access token required" });
    }
    const token = authorization.split(" ")[1];
    try {
        const data = jwt.verify(token, process.env.USER_ACCESS_TOKEN_SECRET);
        if (!data.userId) throw Error("Not authorized");

        const user = await db.User.findOne({ where: { userId: data.userId } });

        if (!user) throw Error("User does not exist");
        req.params.userId = user.userId;

        next();
    } catch (error) {
        console.log(error)
        res.status(401).json({ error: error.message });
    }
}

export default requireUserAuth;