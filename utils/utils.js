import nodemailer from "nodemailer";
import dotenv from 'dotenv';
import Razorpay from "razorpay";
import crypto from "crypto";
dotenv.config();

import { db } from "../models/index.js"
import asyncErrorHandler from "../Error/asyncErrorHandler.js";
import Cart from "../models/order/carts.js";
import ErrorHandler from "../Error/errorHandler.js";
import Product from "../models/product/products.js";
import lockedKeys from "../models/order/lockedKeys.js";
// const { User} = db

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000);
}

export const sendOtpToEmail = asyncErrorHandler(async (req, res, next) => {
    const emailId = req.body.emailId || req.body.email;
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        }
    });

    const otp = generateOTP();

    const mailOptions = {
        from: process.env.email,
        to: emailId,
        subject: 'Email Verification OTP',
        text: `Your OTP for email verification is: ${otp}`
    };

    const info = await transporter.sendMail(mailOptions)

    if (!info) return next(new ErrorHandler("Failed to send otp", 400))

    return otp;
})



export const order = asyncErrorHandler(async (req, res, next) => {
    const amount = req.body.totalAmount;
    if (amount < 0 && amount == null) return next(new ErrorHandler("failed to get the product's price", 400, "either product does not exist or price is below 0 or it is null"));
    const currency = 'INR';
    var razorpay = new Razorpay({ key_id: process.env.razorpay_id, key_secret: process.env.razorpay_secret })
    const options = {
        amount: amount * 100,
        currency: currency,
        receipt: 'order_receipt', // Replace with your custom receipt ID
    };

    const response = await razorpay.orders.create(options);
    if (!response) return next(new ErrorHandler("payment creation failed", 500, "internal server error"));
    return response

})



export const getUserCart = asyncErrorHandler(async (req, res, next) => {

    const userId = req.params.userId;
    const cart = await db.Cart.findOne({ where: { userId } });

    let filteredProducts = [];

    for (const product of cart.products) {
        const p = await db.Product.findOne({
            where: { productId: product.productId },
            include: {
                model: db.ProductKey,
                where: {
                    isSold: false,
                }
            }
        });
        if (p && p.productKeys && p.productKeys.length > 0) filteredProducts.push(product);
    }

    cart.products = filteredProducts;
    await cart.save();

    return cart;
})

export const calculateOrderAmount = asyncErrorHandler(async (req, res, next) => {

    // const userId = req.params.userId;
    const userCart = await getUserCart(req, res, next);

    let totalAmount = 0
    let ind = -1;

    for (let product of userCart.products) {

        ind++;
        const { productId } = product;

        const response = await Product.findByPk(productId, {
            attributes: ['actualPrice']
        })
        userCart.products[ind].price = response['actualPrice'];

        if (response['actualPrice'] > 0 && response['actualPrice'] != null)
            totalAmount += response['actualPrice'] * product['quantity'];
        else return next(new ErrorHandler("failed to get the product's price", 400, "either product does not exist or price is below 0 or it is null"))

    }

    return { totalAmount, userCart };

})

export const sendKeys = async (req, res, next) => {

    const data = req.body.orderDetails
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        }
    });


    let text = `congratulations! Your payment of purchase of antivirus worth ${data.totalPrice} was successful. Here's your product purchase details and productKey delivery`;

    for (let product of data.products) {
        const { name } = await Product.findByPk(product.productId)
        text += `\n Your product keys of product ${name} are : `
        for (let i = 0; i < product.quantity; i++) {
            text += `\n    ${i + 1}. '${product.productKeys[i]}'  `
        }
    }
    

    text += `\n Thank you for shopping with us :)`

    const mailOptions = {
        from: process.env.EMAIL,
        to: 'guptaaayush895@gmail.com',
        subject: 'Purchase confirmation and product delivery',
        text: text
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return next(new ErrorHandler("failed to send Otp", 400, error))
        }
    });

}

export const unlockKeys = asyncErrorHandler(async (req, res, next) => {
    const { products } = await lockedKeys.findOne({ where : { userId : req.body.userCart.userId }});
    
    for(let product of products){
        const { productKeys} = product;
        for(let productKey of productKeys){
            await db.ProductKey.update({
                isSold : false,
            }, {
                where: {
                    productKey : productKey,
                    orderId : null 
                }
            })
        }
    }
})



export const getRandomString = (length) => {
    let chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    let l = chars.length;
    let ans = "";
    for (let i = 0; i < length; i++) {
        ans += chars[Math.floor(Math.random() * l)]
    }
    return ans;
}

export const getImageName = () => {
    return crypto.randomBytes(32).toString("hex");
}

export const searchResult = asyncErrorHandler(async (req, res, next) =>{

    const { key } = req.query;
    const searchTerms = ['products', 'categories', 'brands'];
    const result = {}
    for(let terms of searchTerms){
        const query = `SELECT * FROM ${terms} where LOWER(name) LIKE '%${key}%' `;

        const matchups = await db.sequelize.query(query, {
            replacements: { 
                searchKeyword: `%${key}%` ,
                searchPlace : `${terms}`
            },
            type: db.sequelize.QueryTypes.SELECT
        })
        result[`${terms}`] = matchups 
    }
    res.status(200).json(result);
    
})



