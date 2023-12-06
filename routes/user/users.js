import express from "express";

import {
    userSignIn,
    userSignUp,
    userRefreshToken,
    userLogOut,
    forgotPassword,
    verifyAndRegister,
    verifyAndChangePassword,
} from "../../controllers/user/users.js";
import requireUserAuth from "../../middlewares/requireUserAuth.js";
import { sendOtp } from "../../controllers/verification/emailVerification.js";
import { getCartByUser, updateCart } from "../../controllers/cartOrders/carts.js";
import { checkPayment, createOrder, getAllOrdersOfUser, initiatePayment, paymentFailed } from "../../controllers/cartOrders/orders.js";


const router = express.Router();

// authentication
router.post("/user/signup", userSignUp);
router.post("/user/signin", userSignIn);
router.post("/user/refresh", userRefreshToken);
router.post("/user/logout", userLogOut);


router.post("/user/send-otp", sendOtp);
router.post("/user/signup/verify", verifyAndRegister);
router.post("/user/password", forgotPassword);
router.post("/user/password/verify", verifyAndChangePassword);

// cart routes
router.get('/user/cart', requireUserAuth, getCartByUser);

// only update router because cart table is created when a user is created
router.post('/user/cart', requireUserAuth, updateCart);
// router.post('/user/:userId/cart',  updateCart)

// payment routes
router.post('/user/payment', requireUserAuth, initiatePayment);
router.post('/user/payment/check', requireUserAuth, checkPayment);
router.post('/user/payment/failed', requireUserAuth, paymentFailed);

// order routes
router.get('/user/order', requireUserAuth, getAllOrdersOfUser);
router.post('/user/order', requireUserAuth, createOrder);

export default router;
