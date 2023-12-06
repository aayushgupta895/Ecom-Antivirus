import crypto from "crypto";

import asyncErrorHandler from "../../Error/asyncErrorHandler.js"
import ErrorHandler from "../../Error/errorHandler.js";
import Order from "../../models/order/orders.js";
import { calculateOrderAmount, order, sendKeys, unlockKeys } from "../../utils/utils.js"
import lockedKeys from "../../models/order/lockedKeys.js";
import { db } from "../../models/index.js";
import Product from "../../models/product/products.js";


export const initiatePayment = asyncErrorHandler(async (req, res, next) => {

    const { totalAmount, userCart } = await calculateOrderAmount(req, res, next);

    req.body.totalAmount = totalAmount;
    


    const existingLockedKeys = await lockedKeys.findOne({ where: { userId: userCart.userId } });
    if (existingLockedKeys) {

        
        req.body.userCart = userCart;
        await unlockKeys(req, res, next);

        await lockedKeys.destroy({
            where: {
                userId: req.body.userCart.userId
            }
        })
    }

    req.body.userCart = userCart;
    const isAvailable = await getProductKeys(req, res, next);
    if (!isAvailable) return next(new ErrorHandler("keys not available, order has been sent to pendingDeliveries", 400));

    setTimeout(async () => {
        const key = await lockedKeys.findOne({where : { userId: req.body.userCart.userId }})
        if(`${req.body.keys.createdAt}` != `${key.createdAt}`) return;       //important

        await unlockKeys(req, res, next);
        await lockedKeys.destroy({
            where: {
                userId: req.body.userCart.userId
            }
        })
    }, 1000 * 60 * 4);  // This should be more than what is on the client side otherwise can lead to data inconsistency
    
    const keys = await lockedKeys.create({
        userId: req.body.userCart.userId,
        products: req.body.userCart.products,
        totalPrice: req.body.totalAmount,
    });
    req.body.keys = keys;  // important
    const response = await order(req, res, next);
    res.status(200).json(response);

})


export const checkPayment = asyncErrorHandler(async (req, res, next) => {

    const { order_id, razorpay_payment_id, razorpay_signature } = req.body;

    // Verify the payment signature
    const hmac = crypto.createHmac('sha256', process.env.razorpay_secret); // Replace with your Razorpay Key Secret
    hmac.update(order_id + '|' + razorpay_payment_id);
    const calculatedSignature = hmac.digest('hex');

    if (calculatedSignature === razorpay_signature) {
        // Payment successful

        res.status(200).send({
            success: true,
            status: 200 // important
        })
    } else {

        res.status(400).send({
            success: false,
            status: 400 // important
        })
    }
})


export const createOrder = asyncErrorHandler(async (req, res, next) => {

    const userId = req.params.userId;
    const data = await lockedKeys.findOne({ where: { userId: userId } });
    if (!data) return next(new ErrorHandler("user not found with locked keys", 400));
    const { order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const { products, totalPrice } = data;


    const orderDetails = await db.Order.create({
        razorpay_orderId: order_id,
        userId: userId,
        products: products,
        totalPrice: totalPrice,
        razorpay_payment_id: razorpay_payment_id,
        razorpay_signature: razorpay_signature,
        paymentStatus: "success"
    })

    for (let product of products) {
        const { productKeys, productId } = product;
        for (let productKey of productKeys) {
            await db.ProductKey.update({
                orderId: orderDetails.orderId,
            }, {
                where: {
                    productKey,
                    productId              //important
                }
            })
        }
    }

    
    for(const product of products){
        const pr = await db.Product.findOne({ where : {productId  : product.productId }});
        pr.inStock = pr.inStock - product.quantity;
        await pr.save();
    }

    setTimeout(async ()=>{
        const userCart = await db.Cart.findOne({ where : {userId}});
        userCart.products = [];
        await userCart.save();        
    }, 0)
    
    req.body.orderDetails = orderDetails;
    await sendKeys(req, res, next);

    return res.status(200).json({
        statusCode: 200,
        success: true
    })
})

export const paymentFailed = asyncErrorHandler(async (req, res, next) => {

    const userId = req.params.userId;
    const data = await lockedKeys.findOne({ where: { userId: userId } });
    if (!data) return next(new ErrorHandler("user not found with locked keys", 400))
    const { order_id, razorpay_payment_id, razorpay_signature, reason } = req.body;
    const { products, totalPrice } = data;
    await Order.create({
        razorpay_orderId: order_id,
        userId: userId,
        products: products,
        totalPrice: totalPrice,
        razorpay_payment_id: razorpay_payment_id,
        razorpay_signature: razorpay_signature,
        paymentStatus: "failed",
        paymentFailedReason: reason,
    })

})

export const getProductKeys = async (req, res, next) => {
    
    try {
        const transaction = await db.sequelize.transaction();
        const products = req.body.userCart.products;

        for (let i = 0; i < products.length; i++) {

            req.body.userCart.products[i].productKeys = [];
            const product = products[i];

            const query = `UPDATE "productKeys" SET "isSold" = :newValue

                WHERE "productKeyId" IN (
                SELECT "productKeyId"
                FROM "productKeys"
                WHERE "productId" = :productId AND "isSold" = :oldValue
                LIMIT :quantity
              )
              RETURNING *;`

            const [updatedRows, updatedRowCount] = await db.sequelize.query(
                query,
                {
                    replacements: {
                        newValue: true,
                        productId: product.productId,
                        oldValue: false,
                        quantity: product.quantity,
                    },
                    type: db.sequelize.QueryTypes.UPDATE,
                    transaction: transaction,
                });


            if (updatedRowCount != product.quantity) throw Error({
                message: "required quantity is not available",
                statusCode: 400
            });
            for (const updatedRow of updatedRows) {
                req.body.userCart.products[i].productKeys.push(updatedRow.productKey);
            }
        }
        await transaction.commit();
        return true;
    } catch (error) {
        await transaction.rollback();
        next(new ErrorHandler("keys not available, try after some time", 400));
        return false;
    }
}

export const getAllOrdersOfUser = asyncErrorHandler(async (req, res, next) => {
    const userId = req.params.userId;

    const q = req.query;

    const page = q?.page ? +q.page : 1;
    const limit = q?.limit ? +q.limit : 10;
    const offset = (page - 1) * limit;

    const { count, rows } = await db.Order.findAndCountAll({
        where: {
            userId: userId
        },
        offset,
        limit,
    })

    let totalPages = Math.ceil(count / limit);
    if (!totalPages) totalPages = 0;

    res.status(200).json({
        page,
        limit,
        count: count ? count : 0,
        totalPages,
        data: rows ? rows : [],
    });
})


