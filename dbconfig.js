import dotenv from "dotenv";
dotenv.config();

import { Sequelize } from "sequelize";
import { createClient } from "redis";

export const sequelize = new Sequelize({
    database: process.env.DB_NAME,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: "postgres",
});
await sequelize.authenticate();

export const redisClient = createClient();
redisClient.on('error', err => console.log('Redis Client Error', err));
await redisClient.connect();